// Package twofactor implements TOTP-based 2FA endpoints.
//
//   POST   /2fa/setup           generate secret + provisioning URI
//   POST   /2fa/verify-setup    confirm setup with a TOTP code
//   POST   /2fa/verify          verify a code for already-enabled accounts
//   POST   /2fa/disable         disable 2FA after re-verifying with TOTP/backup
//   POST   /2fa/backup-codes    regenerate backup codes
//   GET    /2fa/status          enabled/verified flags
package twofactor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
)

type Handler struct {
	DB      *sqlx.DB
	AppName string
}

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"2FA"}, OperationID: id}
	}
	huma.Register(api, op(http.MethodPost, "/2fa/setup", "twoFactorSetup"), h.Setup)
	huma.Register(api, op(http.MethodPost, "/2fa/verify-setup", "twoFactorVerifySetup"), h.VerifySetup)
	huma.Register(api, op(http.MethodPost, "/2fa/verify", "twoFactorVerify"), h.Verify)
	huma.Register(api, op(http.MethodPost, "/2fa/disable", "twoFactorDisable"), h.Disable)
	huma.Register(api, op(http.MethodPost, "/2fa/backup-codes", "twoFactorBackupCodes"), h.BackupCodes)
	huma.Register(api, op(http.MethodGet, "/2fa/status", "twoFactorStatus"), h.Status)
}

type TFSetupOutput struct {
	Body struct {
		Secret        string `json:"secret"`
		QRCodeDataURI string `json:"qrCodeDataURI"`
		URI           string `json:"uri"`
	}
}

func (h *Handler) Setup(ctx context.Context, _ *struct{}) (*TFSetupOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var email string
	_ = h.DB.GetContext(ctx, &email, `SELECT email FROM users WHERE id = ?`, uc.UserID)
	issuer := h.AppName
	if issuer == "" {
		issuer = "Palmr"
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, apperr.Internal("totp generate: " + err.Error())
	}
	// Store secret (unverified yet) — verify-setup will flip the flag.
	_, _ = h.DB.ExecContext(ctx,
		`UPDATE users SET twoFactorSecret = ?, twoFactorEnabled = 0, twoFactorVerified = 0, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		key.Secret(), uc.UserID)
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, apperr.Internal("qr: " + err.Error())
	}
	out := &TFSetupOutput{}
	out.Body.Secret = key.Secret()
	out.Body.URI = key.URL()
	out.Body.QRCodeDataURI = "data:image/png;base64," + base64Encode(png)
	return out, nil
}

type TFCodeInput struct {
	Body struct {
		Code string `json:"code" required:"true"`
	}
}
type TFCodesOutput struct {
	Body struct {
		BackupCodes []string `json:"backupCodes"`
	}
}

func (h *Handler) VerifySetup(ctx context.Context, in *TFCodeInput) (*TFCodesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var secret string
	if err := h.DB.GetContext(ctx, &secret, `SELECT twoFactorSecret FROM users WHERE id = ?`, uc.UserID); err != nil || secret == "" {
		return nil, apperr.BadRequest("call /2fa/setup first")
	}
	if !totp.Validate(in.Body.Code, secret) {
		return nil, apperr.Unauthorized("invalid TOTP code")
	}
	codes := genBackupCodes(10)
	csv := strings.Join(codes, ",")
	_, _ = h.DB.ExecContext(ctx,
		`UPDATE users SET twoFactorEnabled = 1, twoFactorVerified = 1, twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		csv, uc.UserID)
	out := &TFCodesOutput{}
	out.Body.BackupCodes = codes
	return out, nil
}

type TFVerifyOutput struct {
	Body struct {
		Valid bool `json:"valid"`
	}
}

func (h *Handler) Verify(ctx context.Context, in *TFCodeInput) (*TFVerifyOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var secret string
	_ = h.DB.GetContext(ctx, &secret, `SELECT twoFactorSecret FROM users WHERE id = ?`, uc.UserID)
	out := &TFVerifyOutput{}
	out.Body.Valid = secret != "" && totp.Validate(in.Body.Code, secret)
	return out, nil
}

func (h *Handler) Disable(ctx context.Context, in *TFCodeInput) (*TFVerifyOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var secret string
	_ = h.DB.GetContext(ctx, &secret, `SELECT twoFactorSecret FROM users WHERE id = ?`, uc.UserID)
	if secret == "" || !totp.Validate(in.Body.Code, secret) {
		return nil, apperr.Unauthorized("invalid code")
	}
	_, _ = h.DB.ExecContext(ctx,
		`UPDATE users SET twoFactorEnabled = 0, twoFactorVerified = 0, twoFactorSecret = NULL, twoFactorBackupCodes = NULL, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		uc.UserID)
	out := &TFVerifyOutput{}
	out.Body.Valid = true
	return out, nil
}

func (h *Handler) BackupCodes(ctx context.Context, _ *struct{}) (*TFCodesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	codes := genBackupCodes(10)
	csv := strings.Join(codes, ",")
	_, _ = h.DB.ExecContext(ctx,
		`UPDATE users SET twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, csv, uc.UserID)
	out := &TFCodesOutput{}
	out.Body.BackupCodes = codes
	return out, nil
}

type TFStatusOutput struct {
	Body struct {
		Enabled  bool `json:"enabled"`
		Verified bool `json:"verified"`
	}
}

func (h *Handler) Status(ctx context.Context, _ *struct{}) (*TFStatusOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &TFStatusOutput{}
	_ = h.DB.QueryRowContext(ctx, `SELECT twoFactorEnabled, twoFactorVerified FROM users WHERE id = ?`, uc.UserID).Scan(&out.Body.Enabled, &out.Body.Verified)
	return out, nil
}

func genBackupCodes(n int) []string {
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		out[i] = strings.ToUpper(hex.EncodeToString(b))
	}
	return out
}

// Tiny base64 wrapper to keep imports terse.
func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, 4*((len(b)+2)/3))
	for i := 0; i < len(b); i += 3 {
		var n uint32
		var pad int
		n |= uint32(b[i]) << 16
		if i+1 < len(b) {
			n |= uint32(b[i+1]) << 8
		} else {
			pad++
		}
		if i+2 < len(b) {
			n |= uint32(b[i+2])
		} else {
			pad++
		}
		out = append(out, alphabet[(n>>18)&63], alphabet[(n>>12)&63])
		if pad < 2 {
			out = append(out, alphabet[(n>>6)&63])
		} else {
			out = append(out, '=')
		}
		if pad < 1 {
			out = append(out, alphabet[n&63])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
