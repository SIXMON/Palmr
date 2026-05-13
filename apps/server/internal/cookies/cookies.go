// Package cookies centralises auth-cookie attributes so every code
// path (register, login, OIDC callback, 2FA) issues identical cookies.
// Matches the legacy `authCookieOptions` from
// apps/server/src/shared/cookies.ts.
package cookies

import (
	"net/http"
	"time"
)

const Name = "token"

// Options describes how Palmr sets its auth cookie.
type Options struct {
	Secure bool
	MaxAge time.Duration
}

// Set writes the cookie to w with the canonical attributes.
func Set(w http.ResponseWriter, token string, opts Options) {
	http.SetCookie(w, &http.Cookie{
		Name:     Name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   opts.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(opts.MaxAge.Seconds()),
	})
}

// Clear instructs the browser to drop the auth cookie. Mirrors the
// fix(auth) from commit 5f8c05f — must match Path/SameSite/Secure of
// Set or the browser ignores the delete.
func Clear(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// Read returns the raw cookie value, or "" if absent.
func Read(r *http.Request) string {
	c, err := r.Cookie(Name)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}
