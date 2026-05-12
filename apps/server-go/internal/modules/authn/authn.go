// Package authn implements the password-login authentication endpoints:
//
//   POST   /auth/login          — email/username + password → session cookie
//   POST   /auth/logout         — revoke current jti + clear cookie
//   GET    /auth/me             — current user (or null when anonymous)
//   GET    /auth/config         — auth config (passwordAuthEnabled, etc.)
//   POST   /auth/forgot-password — request password reset (stub for MVP)
//   POST   /auth/reset-password  — consume reset token (stub for MVP)
//
// 2FA-aware login flow (the legacy backend issues a pre-2FA token then
// upgrades it via /auth/2fa/login) is NOT implemented here yet — TODO
// in the two-factor module. For users with twoFactorEnabled=true this
// MVP returns a 403 telling them to use the legacy endpoint until the
// 2FA module lands.
package authn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	"github.com/sixmon/palmr/apps/server-go/internal/cookies"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
)

type Handler struct {
	DB         *sqlx.DB
	Signer     *auth.Signer
	SecureSite bool
	CookieTTL  time.Duration
}

func RegisterPublic(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/login",
		Tags: []string{"Authentication"}, OperationID: "login",
	}, h.Login)

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
}

// -----------------------------------------------------------------------------
// POST /auth/login
// -----------------------------------------------------------------------------

// LoginInput matches the legacy Fastify schema 1:1 so the web client
// keeps working unchanged: { emailOrUsername, password }.
type LoginInput struct {
	Body struct {
		EmailOrUsername string `json:"emailOrUsername" required:"true" minLength:"1"`
		Password        string `json:"password" required:"true"`
	}
}

type LoginOutput struct {
	Body struct {
		User    publicUser `json:"user"`
		Message string     `json:"message,omitempty"`
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
		return nil, apperr.Unauthorized("invalid credentials")
	}

	if !u.IsActive {
		return nil, apperr.Unauthorized("account is inactive")
	}
	if u.Password == nil || !auth.VerifyPassword(in.Body.Password, *u.Password) {
		return nil, apperr.Unauthorized("invalid credentials")
	}
	if u.TwoFactorEnabled {
		return nil, apperr.Forbidden("2FA is enabled on this account — endpoint not yet ported to Go backend")
	}

	token, err := h.Signer.Sign(u.ID, u.IsAdmin)
	if err != nil {
		return nil, apperr.Internal("issue token")
	}
	out := &LoginOutput{}
	out.Body.User = u.publicUser
	out.SetCookie = http.Cookie{
		Name:     cookies.Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.SecureSite,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.CookieTTL.Seconds()),
	}
	return out, nil
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
