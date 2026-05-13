package auth

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
)

// EnsureAdmin enforces the same rule as the RequireAdmin chi middleware
// but inside a huma handler, so we don't need two separate huma APIs:
//
//   - users table empty → caller is implicitly authorised (bootstrap),
//     and we return a zero UserCtx with the all-mighty flag set
//   - otherwise auth context must exist and be admin
//
// The returned UserCtx is the caller (when authenticated) so handlers
// that need the userId/jti don't have to call FromContext again.
func EnsureAdmin(ctx context.Context, db *sqlx.DB) (UserCtx, error) {
	var n int
	if err := db.GetContext(ctx, &n, `SELECT COUNT(*) FROM users`); err != nil {
		return UserCtx{}, errors.New("database error")
	}
	if n == 0 {
		return UserCtx{IsAdmin: true}, nil
	}
	uc, ok := FromContext(ctx)
	if !ok {
		return UserCtx{}, ErrNoCookie
	}
	if !uc.IsAdmin {
		return UserCtx{}, ErrForbidden
	}
	return uc, nil
}

// EnsureAuth requires a valid auth context (no bootstrap bypass).
func EnsureAuth(ctx context.Context) (UserCtx, error) {
	uc, ok := FromContext(ctx)
	if !ok {
		return UserCtx{}, ErrNoCookie
	}
	return uc, nil
}

var ErrForbidden = newAuthErr("Access restricted to administrators")
