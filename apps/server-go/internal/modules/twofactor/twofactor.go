// Package twofactor implements TOTP-based 2FA endpoints. The legacy
// Fastify backend mounted these under `/auth`, so they share the same
// prefix here for frontend compatibility.
//
//   POST   /auth/2fa/setup           generate secret + provisioning URI
//   POST   /auth/2fa/verify-setup    confirm setup with a TOTP code
//   POST   /auth/2fa/verify          verify a code for already-enabled accounts
//   POST   /auth/2fa/disable         disable 2FA after re-verifying with TOTP/backup
//   POST   /auth/2fa/backup-codes    regenerate backup codes
//   GET    /auth/2fa/status          enabled/verified flags
package twofactor

import (
	dbtypes "github.com/sixmon/palmr/apps/server-go/internal/db"
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
	huma.Register(api, op(http.MethodPost, "/auth/2fa/setup", "twoFactorSetup"), h.Setup)
	huma.Register(api, op(http.MethodPost, "/auth/2fa/verify-setup", "twoFactorVerifySetup"), h.VerifySetup)
	huma.Register(api, op(http.MethodPost, "/auth/2fa/verify", "twoFactorVerify"), h.Verify)
	huma.Register(api, op(http.MethodPost, "/auth/2fa/disable", "twoFactorDisable"), h.Disable)
	huma.Register(api, op(http.MethodPost, "/auth/2fa/backup-codes", "twoFactorBackupCodes"), h.BackupCodes)
	huma.Register(api, op(http.MethodGet, "/auth/2fa/status", "twoFactorStatus"), h.Status)
}

// TFSetupInput accepts an optional appName (issuer) override from the
// frontend — see `TwoFactorSetupRequest` on the web side.
type TFSetupInput struct {
	Body struct {
		AppName string `json:"appName,omitempty"`
	}
}

// BackupCodeView mirrors `BackupCode { code, used }` on the frontend. We
// always return an empty slice during setup — codes are generated and
// shown only after verify-setup, which keeps unverified codes off the
// wire.
type BackupCodeView struct {
	Code string `json:"code"`
	Used bool   `json:"used"`
}

// TFSetupOutput matches `TwoFactorSetupResponse` (web/.../two-factor/types.ts):
// the modal reads `secret`, `qrCode` (data URI), `manualEntryKey` and
// `backupCodes`. The old shape (`qrCodeDataURI`, `uri`) made the QR image
// fail to render in the modal.
type TFSetupOutput struct {
	Body struct {
		Secret         string           `json:"secret"`
		QRCode         string           `json:"qrCode"`
		ManualEntryKey string           `json:"manualEntryKey"`
		BackupCodes    []BackupCodeView `json:"backupCodes"`
	}
}

func (h *Handler) Setup(ctx context.Context, in *TFSetupInput) (*TFSetupOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var email string
	_ = h.DB.GetContext(ctx, &email, `SELECT email FROM users WHERE id = ?`, uc.UserID)
	issuer := in.Body.AppName
	if issuer == "" {
		issuer = h.AppName
	}
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
	dbtypes.LogBestEffort(ctx, "twofactor.store_secret", h.DB,
		`UPDATE users SET twoFactorSecret = ?, twoFactorEnabled = 0, twoFactorVerified = 0, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		key.Secret(), uc.UserID)
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, apperr.Internal("qr: " + err.Error())
	}
	out := &TFSetupOutput{}
	out.Body.Secret = key.Secret()
	out.Body.QRCode = "data:image/png;base64," + base64Encode(png)
	out.Body.ManualEntryKey = formatManualEntry(key.Secret())
	out.Body.BackupCodes = []BackupCodeView{}
	return out, nil
}

// formatManualEntry groups the secret into 4-char chunks separated by
// spaces (the legacy backend did the same), making manual entry less
// error-prone for users who can't scan the QR.
func formatManualEntry(s string) string {
	var sb strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// TFVerifySetupInput mirrors `VerifySetupRequest { token, secret }`. We
// trust the *stored* secret over the body's `secret` field (defense in
// depth — clients can't smuggle an arbitrary secret here) but accept the
// field for schema compat.
type TFVerifySetupInput struct {
	Body struct {
		Token  string `json:"token" required:"true"`
		Secret string `json:"secret,omitempty"`
	}
}

// TFTokenInput is the simpler `{token}` body used by /verify (login flow).
type TFTokenInput struct {
	Body struct {
		Token string `json:"token" required:"true"`
	}
}

// TFCodesOutput matches `VerifySetupResponse { success, backupCodes }` and
// `GenerateBackupCodesResponse { backupCodes }`. The frontend setup hook
// guards the success branch on `response.data.success` — omit it and the
// modal silently fails to advance to the backup-codes screen.
type TFCodesOutput struct {
	Body struct {
		Success     bool     `json:"success"`
		BackupCodes []string `json:"backupCodes"`
	}
}

func (h *Handler) VerifySetup(ctx context.Context, in *TFVerifySetupInput) (*TFCodesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var secret string
	if err := h.DB.GetContext(ctx, &secret, `SELECT twoFactorSecret FROM users WHERE id = ?`, uc.UserID); err != nil || secret == "" {
		return nil, apperr.BadRequest("call /auth/2fa/setup first")
	}
	if !totp.Validate(in.Body.Token, secret) {
		return nil, apperr.Unauthorized("invalid TOTP code")
	}
	codes := genBackupCodes(10)
	csv := strings.Join(codes, ",")
	dbtypes.LogBestEffort(ctx, "twofactor.enable", h.DB,
		`UPDATE users SET twoFactorEnabled = 1, twoFactorVerified = 1, twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		csv, uc.UserID)
	out := &TFCodesOutput{}
	out.Body.Success = true
	out.Body.BackupCodes = codes
	return out, nil
}

// TFVerifyOutput is the `{success, method}` response from `/auth/2fa/verify`
// (login-time check). `method` reports whether the code matched a TOTP or
// a backup code so the frontend can surface that detail.
type TFVerifyOutput struct {
	Body struct {
		Success bool   `json:"success"`
		Method  string `json:"method,omitempty"`
	}
}

func (h *Handler) Verify(ctx context.Context, in *TFTokenInput) (*TFVerifyOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var secret, backupCSV string
	_ = h.DB.QueryRowContext(ctx,
		`SELECT twoFactorSecret, COALESCE(twoFactorBackupCodes, '') FROM users WHERE id = ?`, uc.UserID).
		Scan(&secret, &backupCSV)
	out := &TFVerifyOutput{}
	if secret != "" && totp.Validate(in.Body.Token, secret) {
		out.Body.Success = true
		out.Body.Method = "totp"
		return out, nil
	}
	if backupCSV != "" {
		codes := strings.Split(backupCSV, ",")
		token := strings.ToUpper(strings.TrimSpace(in.Body.Token))
		for i, c := range codes {
			if strings.EqualFold(strings.TrimSpace(c), token) {
				// Burn the code: remove it from the stored list so it can't
				// be reused. Matches the legacy behavior.
				codes = append(codes[:i], codes[i+1:]...)
				dbtypes.LogBestEffort(ctx, "twofactor.burn_backup", h.DB,
					`UPDATE users SET twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
					strings.Join(codes, ","), uc.UserID)
				out.Body.Success = true
				out.Body.Method = "backup"
				return out, nil
			}
		}
	}
	return out, nil
}

// TFDisableInput accepts a password — the legacy Node backend re-verified
// the account password before disabling 2FA (frontend's
// `DisableTwoFactorRequest`). The Go MVP previously asked for a TOTP code
// here which never matched the frontend's `{password}` body and silently
// failed all disable attempts.
type TFDisableInput struct {
	Body struct {
		Password string `json:"password" required:"true"`
	}
}

// TFDisableOutput → `DisableTwoFactorResponse { success }`. The frontend
// branches on `response.data.success` to close the modal.
type TFDisableOutput struct {
	Body struct {
		Success bool `json:"success"`
	}
}

func (h *Handler) Disable(ctx context.Context, in *TFDisableInput) (*TFDisableOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var hash string
	if err := h.DB.GetContext(ctx, &hash, `SELECT COALESCE(password, '') FROM users WHERE id = ?`, uc.UserID); err != nil || hash == "" {
		// No local password (e.g. OAuth-only account) — disabling without
		// a fallback secret would brick the account on the next provider
		// hiccup. Reject explicitly rather than silently disabling.
		return nil, apperr.BadRequest("password not set; cannot verify identity")
	}
	if !auth.VerifyPassword(in.Body.Password, hash) {
		return nil, apperr.Unauthorized("incorrect password")
	}
	dbtypes.LogBestEffort(ctx, "twofactor.disable", h.DB,
		`UPDATE users SET twoFactorEnabled = 0, twoFactorVerified = 0, twoFactorSecret = NULL, twoFactorBackupCodes = NULL, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		uc.UserID)
	out := &TFDisableOutput{}
	out.Body.Success = true
	return out, nil
}

func (h *Handler) BackupCodes(ctx context.Context, _ *struct{}) (*TFCodesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	codes := genBackupCodes(10)
	csv := strings.Join(codes, ",")
	dbtypes.LogBestEffort(ctx, "twofactor.regen_backup", h.DB,
		`UPDATE users SET twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, csv, uc.UserID)
	out := &TFCodesOutput{}
	out.Body.Success = true
	out.Body.BackupCodes = codes
	return out, nil
}

// TFStatusOutput matches `TwoFactorStatus { enabled, verified,
// availableBackupCodes }`. The count is what's left in the CSV — codes get
// burned one-by-one in /auth/2fa/verify.
type TFStatusOutput struct {
	Body struct {
		Enabled              bool `json:"enabled"`
		Verified             bool `json:"verified"`
		AvailableBackupCodes int  `json:"availableBackupCodes"`
	}
}

func (h *Handler) Status(ctx context.Context, _ *struct{}) (*TFStatusOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &TFStatusOutput{}
	var backupCSV string
	_ = h.DB.QueryRowContext(ctx,
		`SELECT twoFactorEnabled, twoFactorVerified, COALESCE(twoFactorBackupCodes, '') FROM users WHERE id = ?`, uc.UserID).
		Scan(&out.Body.Enabled, &out.Body.Verified, &backupCSV)
	if backupCSV != "" {
		// Count non-empty entries — leading/trailing commas can produce
		// empty slots after Split.
		for _, c := range strings.Split(backupCSV, ",") {
			if strings.TrimSpace(c) != "" {
				out.Body.AvailableBackupCodes++
			}
		}
	}
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
