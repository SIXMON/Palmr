package auth

import (
	"context"
	"errors"

	"github.com/jmoiron/sqlx"
)

// EnsureAdmin enforces the same rule as the RequireAdmin chi middleware
// but inside a huma handler, so we don't need two separate huma APIs:
//
//   - users table empty → caller is implicitly authorised (bootstrap)
//   - otherwise auth context must exist and be admin
//
// Returns nil on success, a sentinel error otherwise. Callers wrap into
// the right HTTP status via internal/errors.
func EnsureAdmin(ctx context.Context, db *sqlx.DB) error {
	var n int
	if err := db.GetContext(ctx, &n, `SELECT COUNT(*) FROM users`); err != nil {
		return errors.New("database error")
	}
	if n == 0 {
		return nil
	}
	uc, ok := FromContext(ctx)
	if !ok {
		return ErrNoCookie
	}
	if !uc.IsAdmin {
		return ErrForbidden
	}
	return nil
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
