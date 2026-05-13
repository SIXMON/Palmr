// Package authn implements the password-login authentication endpoints:
//
//   POST   /auth/login          — email/username + password → session cookie
//                                 (or 2FA challenge for 2FA-enabled users)
//   POST   /auth/2fa/login      — finish the 2FA-protected login (TOTP/backup)
//   POST   /auth/logout         — revoke current jti + clear cookie
//   GET    /auth/me             — current user (or null when anonymous)
//   GET    /auth/config         — auth config (passwordAuthEnabled, etc.)
//   POST   /auth/forgot-password — request password reset (stub for MVP)
//   POST   /auth/reset-password  — consume reset token (stub for MVP)
//
// 2FA flow notes
//
// /auth/login authenticates the password. When the user has 2FA enabled we
// look for a long-lived `tdid` (trusted-device) cookie — if its hash matches
// a row in `trusted_devices`, we treat the device as already proven and
// issue the session cookie directly. Otherwise we return 200 with
// `{requiresTwoFactor: true, userId, message}` and *no* session cookie; the
// frontend then collects a TOTP/backup code and POSTs it to /auth/2fa/login,
// which validates it and finally issues the session cookie (plus a new
// trusted-device cookie when `rememberDevice` is set).
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pquerna/otp/totp"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	"github.com/sixmon/palmr/apps/server/internal/cookies"
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

// totpValidate is a thin alias for `totp.Validate` so the call sites read
// naturally inside this package.
func totpValidate(code, secret string) bool { return totp.Validate(code, secret) }

// Trusted-device cookie config. The cookie holds an opaque random ID; the
// SHA-256 of that ID is stored as `deviceHash` server-side so a leaked DB
// row alone can't be used to forge the cookie.
const (
	trustedDeviceCookieName = "tdid"
	trustedDeviceTTL        = 30 * 24 * time.Hour // 30 days, mirrors legacy
)

// Mailer is the narrow contract authn needs from the email service —
// keeps an import cycle out of the package boundary (email already
// depends on auth.EnsureAuth through its admin SMTP-test endpoint).
type Mailer interface {
	Send(ctx context.Context, to, subject, htmlBody string) error
}

type Handler struct {
	DB         *sqlx.DB
	Signer     *auth.Signer
	SecureSite bool
	CookieTTL  time.Duration
	Mailer     Mailer // optional — when nil, /auth/forgot-password is a no-op
}

func RegisterPublic(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/login",
		Tags: []string{"Authentication"}, OperationID: "login",
	}, h.Login)

	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/2fa/login",
		Tags: []string{"Authentication"}, OperationID: "completeTwoFactorLogin",
	}, h.CompleteTwoFactorLogin)

	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/logout",
		Tags: []string{"Authentication"}, OperationID: "logout",
	}, h.Logout)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/auth/me",
		Tags: []string{"Authentication"}, OperationID: "getCurrentUser",
	}, h.Me)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/auth/config",
		Tags: []string{"Authentication"}, OperationID: "getAuthConfig",
	}, h.AuthConfig)

	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/forgot-password",
		Tags: []string{"Authentication"}, OperationID: "requestPasswordReset",
	}, h.ForgotPassword)

	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/reset-password",
		Tags: []string{"Authentication"}, OperationID: "resetPassword",
	}, h.ResetPassword)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/auth/trusted-devices",
		Tags: []string{"Authentication"}, OperationID: "listTrustedDevices",
	}, h.ListTrustedDevices)

	huma.Register(api, huma.Operation{
		Method: http.MethodDelete, Path: "/auth/trusted-devices/{id}",
		Tags: []string{"Authentication"}, OperationID: "removeTrustedDevice",
	}, h.RemoveTrustedDevice)

	huma.Register(api, huma.Operation{
		Method: http.MethodDelete, Path: "/auth/trusted-devices",
		Tags: []string{"Authentication"}, OperationID: "removeAllTrustedDevices",
	}, h.RemoveAllTrustedDevices)
}

// -----------------------------------------------------------------------------
// POST /auth/login
// -----------------------------------------------------------------------------

// LoginInput matches the legacy Fastify schema 1:1 so the web client
// keeps working unchanged: { emailOrUsername, password }. We also read
// the raw Cookie header so the handler can spot a previously-issued
// trusted-device cookie and skip the 2FA challenge.
type LoginInput struct {
	Body struct {
		EmailOrUsername string `json:"emailOrUsername" required:"true" minLength:"1"`
		Password        string `json:"password" required:"true"`
	}
	CookieHeader string `header:"Cookie"`
	UserAgent    string `header:"User-Agent"`
	XForwardFor  string `header:"X-Forwarded-For"`
}

// LoginOutput carries either the authenticated user + session cookie or a
// 2FA challenge (`RequiresTwoFactor + UserID`). The frontend's
// `LoginResponse` type (apps/web/.../two-factor/types.ts) declares all
// three as optional and branches on `requiresTwoFactor`.
type LoginOutput struct {
	Body struct {
		User              *publicUser `json:"user,omitempty"`
		Message           string      `json:"message,omitempty"`
		RequiresTwoFactor bool        `json:"requiresTwoFactor,omitempty"`
		UserID            string      `json:"userId,omitempty"`
	}
	SetCookie http.Cookie `header:"Set-Cookie"`
}

type publicUser struct {
	ID        string  `db:"id"        json:"id"`
	FirstName string  `db:"firstName" json:"firstName"`
	LastName  string  `db:"lastName"  json:"lastName"`
	Username  string  `db:"username"  json:"username"`
	Email     string  `db:"email"     json:"email"`
	Image     *string `db:"image"     json:"image"`
	IsAdmin   bool    `db:"isAdmin"   json:"isAdmin"`
}

func (h *Handler) Login(ctx context.Context, in *LoginInput) (*LoginOutput, error) {
	login := strings.TrimSpace(strings.ToLower(in.Body.EmailOrUsername))
	if login == "" || in.Body.Password == "" {
		return nil, apperr.BadRequest("login and password are required")
	}

	var u struct {
		publicUser
		Password         *string `db:"password"`
		IsActive         bool    `db:"isActive"`
		TwoFactorEnabled bool    `db:"twoFactorEnabled"`
	}
	err := h.DB.GetContext(ctx, &u, `
		SELECT id, firstName, lastName, username, email, image, isAdmin, isActive, password, twoFactorEnabled
		FROM users WHERE email = ? OR username = ?`, login, login)
	if err != nil {
		// Unknown account: don't reveal which axis (email/username) failed,
		// just return invalid credentials. We *do not* throttle on unknown
		// logins because there's no user_id to bind the counter to — adding
		// IP-based throttling would belong at the reverse proxy.
		return nil, apperr.Unauthorized("invalid credentials")
	}

	if !u.IsActive {
		return nil, apperr.Unauthorized("account is inactive")
	}

	// Throttle: refuse the request before bcrypt if the user is locked out.
	maxAttempts, blockSeconds := h.throttleConfig(ctx)
	if maxAttempts > 0 {
		blocked, retryAfter, err := h.isBlocked(ctx, u.ID, maxAttempts, blockSeconds)
		if err == nil && blocked {
			return nil, apperr.Unauthorized(
				"too many failed login attempts; try again in " + retryAfter.Round(time.Second).String())
		}
	}

	if u.Password == nil || !auth.VerifyPassword(in.Body.Password, *u.Password) {
		// Bump the counter (best effort; we don't block the response on a
		// counter write failure).
		_ = h.recordFailure(ctx, u.ID)
		return nil, apperr.Unauthorized("invalid credentials")
	}

	if u.TwoFactorEnabled {
		// Trusted-device fast path: if the browser presents a `tdid` cookie
		// whose SHA-256 matches an unexpired row in trusted_devices for
		// this user, we treat the device as already 2FA-verified.
		if rawID := cookieValueFromHeader(in.CookieHeader, trustedDeviceCookieName); rawID != "" {
			if h.consumeTrustedDevice(ctx, u.ID, rawID) {
				return h.issueSession(u.publicUser, u.IsAdmin), nil
			}
		}
		// Hand off to /auth/2fa/login. No session cookie is set yet.
		out := &LoginOutput{}
		out.Body.RequiresTwoFactor = true
		out.Body.UserID = u.ID
		out.Body.Message = "two-factor authentication required"
		return out, nil
	}

	// Successful login: clear the failure counter so the user starts fresh
	// next time they sign out.
	_ = h.resetFailures(ctx, u.ID)
	return h.issueSession(u.publicUser, u.IsAdmin), nil
}

// issueSession packages a successful login response: signed JWT in the
// session cookie + the public-user body the frontend expects.
func (h *Handler) issueSession(pu publicUser, isAdmin bool) *LoginOutput {
	token, _ := h.Signer.Sign(pu.ID, isAdmin)
	out := &LoginOutput{}
	user := pu
	out.Body.User = &user
	out.SetCookie = http.Cookie{
		Name:     cookies.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.SecureSite,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.CookieTTL.Seconds()),
	}
	return out
}

// cookieValueFromHeader pulls a single cookie value out of a raw Cookie
// header. Avoids reaching into the *http.Request, which huma's input
// model doesn't expose directly.
func cookieValueFromHeader(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// consumeTrustedDevice verifies a trusted-device cookie value. We hash the
// raw cookie ID with SHA-256 and look it up — the DB never stores the
// plaintext ID, so a snapshot of `trusted_devices` alone can't be used to
// forge the cookie. On match we bump lastUsedAt as a soft "still in use"
// signal.
func (h *Handler) consumeTrustedDevice(ctx context.Context, userID, rawID string) bool {
	hash := sha256Hex(rawID)
	var id string
	var expires dbtypes.PrismaTime
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, expiresAt FROM trusted_devices WHERE userId = ? AND deviceHash = ?`,
		userID, hash).Scan(&id, &expires)
	if err != nil {
		return false
	}
	if time.Now().After(expires.Time) {
		// Expired — clean up so the table doesn't bloat.
		_, _ = h.DB.ExecContext(ctx, `DELETE FROM trusted_devices WHERE id = ?`, id)
		return false
	}
	dbtypes.LogBestEffort(ctx, "authn.touch_trusted_device", h.DB,
		`UPDATE trusted_devices SET lastUsedAt = CURRENT_TIMESTAMP, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return true
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// -----------------------------------------------------------------------------
// POST /auth/2fa/login — complete the 2FA-challenged login flow.
// -----------------------------------------------------------------------------

// TwoFactorLoginInput accepts {userId, token, rememberDevice}, matching the
// frontend's `CompleteTwoFactorLoginRequest`. We also peek at User-Agent and
// X-Forwarded-For so the trusted_devices row carries useful labels.
type TwoFactorLoginInput struct {
	Body struct {
		UserID         string `json:"userId" required:"true"`
		Token          string `json:"token" required:"true"`
		RememberDevice bool   `json:"rememberDevice,omitempty"`
	}
	UserAgent   string `header:"User-Agent"`
	XForwardFor string `header:"X-Forwarded-For"`
}

// TwoFactorLoginOutput carries the same {user} body as /auth/login. Cookies
// are written as a *slice* — huma calls `AppendHeader` for slice fields and
// `SetHeader` (overwrite) for non-slice fields, so we'd overwrite the
// session cookie with the trusted-device cookie if we used two scalar
// fields.
type TwoFactorLoginOutput struct {
	Body struct {
		User    *publicUser `json:"user,omitempty"`
		Message string      `json:"message,omitempty"`
	}
	SetCookies []http.Cookie `header:"Set-Cookie"`
}

func (h *Handler) CompleteTwoFactorLogin(ctx context.Context, in *TwoFactorLoginInput) (*TwoFactorLoginOutput, error) {
	if in.Body.UserID == "" || in.Body.Token == "" {
		return nil, apperr.BadRequest("userId and token are required")
	}
	// Pull everything we need to (a) verify the code and (b) hand the
	// frontend a publicUser body identical to /auth/login.
	var u struct {
		publicUser
		IsActive         bool   `db:"isActive"`
		TwoFactorEnabled bool   `db:"twoFactorEnabled"`
		TwoFactorSecret  string `db:"twoFactorSecret"`
		BackupCSV        string `db:"twoFactorBackupCodes"`
	}
	err := h.DB.GetContext(ctx, &u, `
		SELECT id, firstName, lastName, username, email, image, isAdmin, isActive,
		       twoFactorEnabled, COALESCE(twoFactorSecret, '') AS twoFactorSecret,
		       COALESCE(twoFactorBackupCodes, '') AS twoFactorBackupCodes
		FROM users WHERE id = ?`, in.Body.UserID)
	if err != nil {
		return nil, apperr.Unauthorized("invalid credentials")
	}
	if !u.IsActive || !u.TwoFactorEnabled || u.TwoFactorSecret == "" {
		return nil, apperr.Unauthorized("two-factor not initialised for this account")
	}

	// Same throttle gating as /auth/login — protects the 2FA code-guessing
	// surface, which has only ~10⁶ valid codes at any moment.
	maxAttempts, blockSeconds := h.throttleConfig(ctx)
	if maxAttempts > 0 {
		blocked, retryAfter, err := h.isBlocked(ctx, u.ID, maxAttempts, blockSeconds)
		if err == nil && blocked {
			return nil, apperr.Unauthorized(
				"too many failed login attempts; try again in " + retryAfter.Round(time.Second).String())
		}
	}

	if !h.validate2FAToken(ctx, u.ID, in.Body.Token, u.TwoFactorSecret, u.BackupCSV) {
		_ = h.recordFailure(ctx, u.ID)
		return nil, apperr.Unauthorized("invalid two-factor code")
	}
	_ = h.resetFailures(ctx, u.ID)

	// Issue the regular session cookie.
	token, err := h.Signer.Sign(u.ID, u.IsAdmin)
	if err != nil {
		return nil, apperr.Internal("issue token")
	}
	out := &TwoFactorLoginOutput{}
	user := u.publicUser
	out.Body.User = &user
	out.SetCookies = []http.Cookie{{
		Name:     cookies.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.SecureSite,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.CookieTTL.Seconds()),
	}}

	// Optional: trust this device for `trustedDeviceTTL`.
	if in.Body.RememberDevice {
		if raw := h.rememberDevice(ctx, u.ID, in.UserAgent, firstHop(in.XForwardFor)); raw != "" {
			out.SetCookies = append(out.SetCookies, http.Cookie{
				Name:     trustedDeviceCookieName,
				Value:    raw,
				Path:     "/",
				HttpOnly: true,
				Secure:   h.SecureSite,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(trustedDeviceTTL.Seconds()),
			})
		}
	}
	return out, nil
}

// validate2FAToken accepts a TOTP code OR a backup code. Backup codes get
// burned on use (matches the legacy backend's behaviour and what the
// stand-alone /auth/2fa/verify endpoint does).
func (h *Handler) validate2FAToken(ctx context.Context, userID, token, secret, backupCSV string) bool {
	if totpValidate(token, secret) {
		return true
	}
	if backupCSV == "" {
		return false
	}
	wanted := strings.ToUpper(strings.TrimSpace(token))
	codes := strings.Split(backupCSV, ",")
	for i, c := range codes {
		if strings.EqualFold(strings.TrimSpace(c), wanted) {
			codes = append(codes[:i], codes[i+1:]...)
			dbtypes.LogBestEffort(ctx, "authn.burn_backup_code", h.DB,
				`UPDATE users SET twoFactorBackupCodes = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
				strings.Join(codes, ","), userID)
			return true
		}
	}
	return false
}

// rememberDevice generates a fresh random ID, stores its SHA-256 hash in
// trusted_devices, and returns the raw ID for the cookie value. Returns
// `""` if anything failed (caller just skips the cookie in that case).
func (h *Handler) rememberDevice(ctx context.Context, userID, ua, ip string) string {
	idBuf := make([]byte, 32)
	if _, err := rand.Read(idBuf); err != nil {
		return ""
	}
	raw := hex.EncodeToString(idBuf)
	hash := sha256Hex(raw)
	now := time.Now().UTC()
	expires := now.Add(trustedDeviceTTL)
	rowID := uuid.NewString()
	// Truncate UA to keep DB rows reasonable. Browsers can send 500+ char
	// UA strings.
	if len(ua) > 256 {
		ua = ua[:256]
	}
	deviceName := truncate(ua, 80)
	_, err := h.DB.ExecContext(ctx, `
		INSERT INTO trusted_devices (id, userId, deviceHash, deviceName, userAgent, ipAddress, lastUsedAt, expiresAt, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rowID, userID, hash, deviceName, ua, ip, now, expires, now, now)
	if err != nil {
		return ""
	}
	return raw
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstHop(xff string) string {
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
}

// -----------------------------------------------------------------------------
// Login throttling helpers — reads the limits from app_configs each call so
// admins can adjust without restarting. Cheap (single-key indexed lookup).
// -----------------------------------------------------------------------------

func (h *Handler) throttleConfig(ctx context.Context) (maxAttempts int, blockSeconds int) {
	var maxStr, blockStr string
	_ = h.DB.GetContext(ctx, &maxStr, `SELECT value FROM app_configs WHERE key = 'maxLoginAttempts'`)
	_ = h.DB.GetContext(ctx, &blockStr, `SELECT value FROM app_configs WHERE key = 'loginBlockDuration'`)
	maxAttempts, _ = strconv.Atoi(maxStr)
	blockSeconds, _ = strconv.Atoi(blockStr)
	if maxAttempts < 0 {
		maxAttempts = 0
	}
	if blockSeconds < 0 {
		blockSeconds = 0
	}
	return
}

// isBlocked reports whether the user is currently locked out. The lock
// window expires `blockSeconds` after the *last* failed attempt — once
// the window passes the counter is treated as zero and the next failure
// starts a fresh streak.
func (h *Handler) isBlocked(ctx context.Context, userID string, maxAttempts, blockSeconds int) (bool, time.Duration, error) {
	var attempts int
	var last dbtypes.PrismaTime
	err := h.DB.QueryRowContext(ctx,
		`SELECT attempts, lastAttempt FROM login_attempts WHERE userId = ?`, userID).
		Scan(&attempts, &last)
	if err != nil {
		// No row yet → never failed.
		return false, 0, nil
	}
	if attempts < maxAttempts {
		return false, 0, nil
	}
	window := time.Duration(blockSeconds) * time.Second
	deadline := last.Time.Add(window)
	if time.Now().After(deadline) {
		return false, 0, nil
	}
	return true, time.Until(deadline), nil
}

// recordFailure atomically bumps the failure counter. If the lockout
// window has already expired we restart from 1 — otherwise we keep
// incrementing, which is what produces the lockout once `maxAttempts`
// is reached.
func (h *Handler) recordFailure(ctx context.Context, userID string) error {
	now := time.Now().UTC()
	// Upsert: on conflict we increment, but reset to 1 if the previous
	// lastAttempt is older than the configured window — otherwise a user
	// who failed 5 times a year ago would be permanently locked out.
	_, blockSeconds := h.throttleConfig(ctx)
	cutoff := now.Add(-time.Duration(blockSeconds) * time.Second)
	_, err := h.DB.ExecContext(ctx, `
		INSERT INTO login_attempts (id, userId, attempts, lastAttempt)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(userId) DO UPDATE SET
		  attempts = CASE
		    WHEN login_attempts.lastAttempt < ? THEN 1
		    ELSE login_attempts.attempts + 1
		  END,
		  lastAttempt = excluded.lastAttempt`,
		uuid.NewString(), userID, now, cutoff)
	return err
}

func (h *Handler) resetFailures(ctx context.Context, userID string) error {
	_, err := h.DB.ExecContext(ctx, `DELETE FROM login_attempts WHERE userId = ?`, userID)
	return err
}

// -----------------------------------------------------------------------------
// POST /auth/logout — revoke current jti and clear cookie.
// -----------------------------------------------------------------------------

type LogoutOutput struct {
	Body struct {
		Message string `json:"message"`
	}
	SetCookie http.Cookie `header:"Set-Cookie"`
}

func (h *Handler) Logout(ctx context.Context, _ *struct{}) (*LogoutOutput, error) {
	uc, ok := auth.FromContext(ctx)
	if ok && uc.JTI != "" {
		auth.RevokeJTI(uc.JTI)
	}
	out := &LogoutOutput{}
	out.Body.Message = "logged out"
	out.SetCookie = http.Cookie{
		Name:     cookies.Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.SecureSite,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /auth/me — return the authenticated user, or {"user": null}.
//
// This endpoint is auth-OPTIONAL: it never returns 401. The legacy
// backend uses this idiom so the frontend can check authentication
// without dealing with errors.
// -----------------------------------------------------------------------------

type MeOutput struct {
	Body struct {
		User *publicUser `json:"user"`
	}
}

// MeRawHandler is a plain net/http handler so we can read the cookie
// directly. Huma doesn't expose the raw request in middlewares well
// enough to do the same "no-cookie ⇒ null" trick from inside huma.
func (h *Handler) Me(ctx context.Context, _ *struct{}) (*MeOutput, error) {
	out := &MeOutput{}

	uc, ok := auth.FromContext(ctx)
	if !ok {
		return out, nil // user: null
	}

	var u publicUser
	err := h.DB.GetContext(ctx, &u,
		`SELECT id, firstName, lastName, username, email, image, isAdmin
		 FROM users WHERE id = ? AND isActive = 1`, uc.UserID)
	if err != nil {
		if errors.Is(err, errNoRows) {
			return out, nil
		}
		return out, nil
	}
	out.Body.User = &u
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /auth/config — frontend uses this to know whether to show the
// password form (vs OIDC-only).
// -----------------------------------------------------------------------------

type AuthConfigOutput struct {
	Body struct {
		PasswordAuthEnabled bool `json:"passwordAuthEnabled"`
		OIDCAuthEnabled     bool `json:"oidcAuthEnabled"`
	}
}

func (h *Handler) AuthConfig(ctx context.Context, _ *struct{}) (*AuthConfigOutput, error) {
	out := &AuthConfigOutput{}
	out.Body.PasswordAuthEnabled = h.configBool(ctx, "passwordAuthEnabled", true)
	out.Body.OIDCAuthEnabled = false // TODO: scan auth_providers table when port lands
	return out, nil
}

func (h *Handler) configBool(ctx context.Context, key string, def bool) bool {
	var v string
	err := h.DB.GetContext(ctx, &v, `SELECT value FROM app_configs WHERE key = ?`, key)
	if err != nil {
		return def
	}
	switch strings.ToLower(v) {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}

// Convenience errNoRows alias to avoid importing database/sql here when we
// already pull it transitively through sqlx.
var errNoRows = errors.New("sql: no rows in result set")

// -----------------------------------------------------------------------------
// POST /auth/forgot-password  { email, origin } → { message }
// -----------------------------------------------------------------------------

type ForgotPasswordInput struct {
	Body struct {
		Email  string `json:"email" required:"true" format:"email"`
		Origin string `json:"origin" required:"true"`
	}
}
type MessageOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (h *Handler) ForgotPassword(ctx context.Context, in *ForgotPasswordInput) (*MessageOutput, error) {
	// Always answer the same way so we don't leak which emails are
	// registered (account-enumeration defence).
	out := &MessageOutput{}
	out.Body.Message = "If an account exists for this email, a reset link has been sent."

	email := strings.TrimSpace(strings.ToLower(in.Body.Email))
	var userID string
	if err := h.DB.GetContext(ctx, &userID,
		`SELECT id FROM users WHERE email = ? AND isActive = 1`, email); err != nil {
		return out, nil
	}

	// TTL from app_configs (passwordResetTokenExpiration, seconds).
	ttlSec := 3600
	var v string
	if err := h.DB.GetContext(ctx, &v,
		`SELECT value FROM app_configs WHERE key = 'passwordResetTokenExpiration'`); err == nil {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			ttlSec = n
		}
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, apperr.Internal("generate token")
	}
	token := hex.EncodeToString(tokenBytes)
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(ttlSec) * time.Second)

	// Wipe any previous outstanding reset for this user — only the latest
	// link should work, matches the legacy backend.
	dbtypes.LogBestEffort(ctx, "authn.authn.delete.from.password_resets.where", h.DB, `DELETE FROM password_resets WHERE userId = ? AND used = 0`, userID)

	if _, err := h.DB.ExecContext(ctx, `
		INSERT INTO password_resets (id, userId, token, expiresAt, used, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, 0, ?, ?)`,
		uuid.NewString(), userID, token, expiresAt, now, now); err != nil {
		return nil, apperr.Internal("create reset")
	}

	// Send the email. If SMTP isn't configured, log + still pretend success.
	if h.Mailer != nil {
		origin := strings.TrimRight(in.Body.Origin, "/")
		link := origin + "/reset-password?token=" + token
		htmlBody := `<p>Click the link below to reset your password. The link expires in ` +
			(time.Duration(ttlSec) * time.Second).String() + `.</p>` +
			`<p><a href="` + link + `">` + link + `</a></p>` +
			`<p>If you didn't request this, ignore this email.</p>`
		_ = h.Mailer.Send(ctx, email, "Reset your Palmr password", htmlBody)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// POST /auth/reset-password  { token, password } → { message }
// -----------------------------------------------------------------------------

type ResetPasswordInput struct {
	Body struct {
		Token    string `json:"token" required:"true" minLength:"32"`
		Password string `json:"password" required:"true" minLength:"8" maxLength:"72"`
	}
}

func (h *Handler) ResetPassword(ctx context.Context, in *ResetPasswordInput) (*MessageOutput, error) {
	var (
		userID    string
		expiresAt dbtypes.PrismaTime
		used      bool
	)
	err := h.DB.QueryRowContext(ctx,
		`SELECT userId, expiresAt, used FROM password_resets WHERE token = ?`, in.Body.Token).
		Scan(&userID, &expiresAt, &used)
	if err != nil {
		return nil, apperr.BadRequest("invalid or expired token")
	}
	if used {
		return nil, apperr.BadRequest("this reset link has already been used")
	}
	if time.Now().After(expiresAt.Time) {
		return nil, apperr.BadRequest("this reset link has expired")
	}

	hash, err := auth.HashPassword(in.Body.Password, 12)
	if err != nil {
		return nil, apperr.BadRequest(err.Error())
	}

	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin tx")
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		hash, userID); err != nil {
		return nil, apperr.Internal("update password")
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE password_resets SET used = 1, updatedAt = CURRENT_TIMESTAMP WHERE token = ?`,
		in.Body.Token); err != nil {
		return nil, apperr.Internal("mark token used")
	}
	// Wipe failed-login throttle on success so the user isn't bounced
	// straight after resetting.
	dbtypes.LogBestEffort(ctx, "authn.authn.delete.from.login_attempts.where", tx, `DELETE FROM login_attempts WHERE userId = ?`, userID)

	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit reset")
	}

	out := &MessageOutput{}
	out.Body.Message = "Password updated. You can now log in."
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /auth/trusted-devices             — list mine
// DELETE /auth/trusted-devices/{id}     — remove one
// DELETE /auth/trusted-devices          — clear all mine
//
// Used by the 2FA "remember this device for 30 days" flow on the legacy
// backend. Whether or not the 2FA module here actually issues trusted
// device cookies, the admin UI lists what's in the table so the user
// can audit/clean it up.
// -----------------------------------------------------------------------------

type TrustedDevice struct {
	ID         string             `db:"id"         json:"id"`
	DeviceName *string            `db:"deviceName" json:"deviceName"`
	UserAgent  *string            `db:"userAgent"  json:"userAgent"`
	IPAddress  *string            `db:"ipAddress"  json:"ipAddress"`
	CreatedAt  dbtypes.PrismaTime `db:"createdAt"  json:"createdAt"`
	LastUsedAt dbtypes.PrismaTime `db:"lastUsedAt" json:"lastUsedAt"`
	ExpiresAt  dbtypes.PrismaTime `db:"expiresAt"  json:"expiresAt"`
}

type TrustedDevicesOutput struct {
	Body struct {
		Devices []TrustedDevice `json:"devices"`
	}
}

func (h *Handler) ListTrustedDevices(ctx context.Context, _ *struct{}) (*TrustedDevicesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &TrustedDevicesOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null` —
	// the React hook in apps/web does `devices.length` and crashes on null.
	out.Body.Devices = []TrustedDevice{}
	_ = h.DB.SelectContext(ctx, &out.Body.Devices, `
		SELECT id, deviceName, userAgent, ipAddress, createdAt, lastUsedAt, expiresAt
		FROM trusted_devices WHERE userId = ? ORDER BY lastUsedAt DESC`, uc.UserID)
	return out, nil
}

type RemoveTrustedDeviceInput struct{ ID string `path:"id"` }
type RemoveTrustedDeviceOutput struct {
	Body struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

func (h *Handler) RemoveTrustedDevice(ctx context.Context, in *RemoveTrustedDeviceInput) (*RemoveTrustedDeviceOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	res, err := h.DB.ExecContext(ctx,
		`DELETE FROM trusted_devices WHERE id = ? AND userId = ?`, in.ID, uc.UserID)
	if err != nil {
		return nil, apperr.Internal("delete device")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, apperr.NotFound("device not found")
	}
	out := &RemoveTrustedDeviceOutput{}
	out.Body.Success = true
	out.Body.Message = "device removed"
	return out, nil
}

type RemoveAllTrustedDevicesOutput struct {
	Body struct {
		Success      bool   `json:"success"`
		Message      string `json:"message"`
		RemovedCount int64  `json:"removedCount"`
	}
}

func (h *Handler) RemoveAllTrustedDevices(ctx context.Context, _ *struct{}) (*RemoveAllTrustedDevicesOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	res, err := h.DB.ExecContext(ctx,
		`DELETE FROM trusted_devices WHERE userId = ?`, uc.UserID)
	if err != nil {
		return nil, apperr.Internal("delete devices")
	}
	n, _ := res.RowsAffected()
	out := &RemoveAllTrustedDevicesOutput{}
	out.Body.Success = true
	out.Body.RemovedCount = n
	out.Body.Message = "all devices removed"
	return out, nil
}
