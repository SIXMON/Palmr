package auth

import (
	"context"
	"net/http"

	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/cookies"
)

type ctxKey int

const userCtxKey ctxKey = iota

// UserCtx is what handlers receive after a passing requireAuth/requireAdmin.
type UserCtx struct {
	UserID  string
	IsAdmin bool
	Active  bool
	JTI     string
}

// FromContext returns the auth context attached by the middleware, or
// (zero, false) if the request was unauthenticated (only possible on
// routes that don't require auth).
func FromContext(ctx context.Context) (UserCtx, bool) {
	u, ok := ctx.Value(userCtxKey).(UserCtx)
	return u, ok
}

// WithUser stamps the given user onto the context. Exposed so the
// auth-optional middleware in main.go can attach claims without owning
// the private key type.
func WithUser(parent context.Context, uc UserCtx) context.Context {
	return context.WithValue(parent, userCtxKey, uc)
}

// Middleware bundles dependencies for the auth hooks.
type Middleware struct {
	Signer     *Signer
	DB         *sqlx.DB
	SecureSite bool
}

// RequireAuth is a net/http middleware that:
//   - parses the JWT cookie, verifies signature + expiry + jti revocation
//   - loads the user from the DB and rejects deactivated accounts
//   - on any failure clears the cookie before replying 401 (so the browser
//     stops replaying a dead token — see fix 5f8c05f).
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uc, err := m.authenticate(r)
		if err != nil {
			if cookies.Read(r) != "" {
				cookies.Clear(w, m.SecureSite)
			}
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, uc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is RequireAuth + admin check, with the same bootstrap
// bypass the legacy backend uses: when the users table is empty, we let
// the request through unauthenticated so the very first admin can be
// created.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		if err := m.DB.GetContext(r.Context(), &n, `SELECT COUNT(*) FROM users`); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		if n == 0 {
			// Bootstrap path: drop any stale token so the response's
			// freshly-issued cookie isn't shadowed by the old one.
			if cookies.Read(r) != "" {
				cookies.Clear(w, m.SecureSite)
			}
			next.ServeHTTP(w, r)
			return
		}

		uc, err := m.authenticate(r)
		if err != nil {
			if cookies.Read(r) != "" {
				cookies.Clear(w, m.SecureSite)
			}
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if !uc.IsAdmin {
			http.Error(w, "Access restricted to administrators", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, uc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate performs the JWT-verify + DB-lookup dance shared by
// RequireAuth and RequireAdmin. Returns an error suitable for the 401
// body — callers attach the cookie-clear themselves.
func (m *Middleware) authenticate(r *http.Request) (UserCtx, error) {
	raw := cookies.Read(r)
	if raw == "" {
		return UserCtx{}, ErrNoCookie
	}
	c, err := m.Signer.Verify(raw)
	if err != nil {
		return UserCtx{}, err
	}
	var u struct {
		IsAdmin  bool `db:"isAdmin"`
		IsActive bool `db:"isActive"`
	}
	err = m.DB.GetContext(r.Context(), &u,
		`SELECT isAdmin, isActive FROM users WHERE id = ?`, c.UserID)
	if err != nil {
		return UserCtx{}, ErrUserGone
	}
	if !u.IsActive {
		return UserCtx{}, ErrAccountInactive
	}
	return UserCtx{
		UserID:  c.UserID,
		IsAdmin: u.IsAdmin,
		Active:  true,
		JTI:     c.JTI,
	}, nil
}

// Sentinel errors so handlers can pattern-match if needed.
var (
	ErrNoCookie        = newAuthErr("Unauthorized: a valid token is required to access this resource.")
	ErrUserGone        = newAuthErr("Session expired. Please log in again.")
	ErrAccountInactive = newAuthErr("Account is inactive")
)

type authErr struct{ msg string }

func (e *authErr) Error() string   { return e.msg }
func newAuthErr(m string) *authErr { return &authErr{msg: m} }
