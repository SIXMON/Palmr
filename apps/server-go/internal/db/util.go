package db

import (
	"context"
	"database/sql"
	"log/slog"
)

// Execer is satisfied by *sqlx.DB and *sqlx.Tx — anything that can
// run an Exec. The helpers in this file are deliberately interface-typed
// so callers can pass either without ceremony.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// LogBestEffort runs a fire-and-forget Exec, logging at WARN if it
// fails. Use ONLY when the caller is genuinely OK with the write
// being dropped — best-effort cleanup, secondary counters, cache
// invalidation. Anything the caller's response cares about must
// surface the error itself.
//
// Argument order is (ctx, op, ex, query, args...) — `op` is the label
// that ends up in the structured log so operators can grep for it.
// Keep it short and stable, e.g. "share.delete.recipients".
func LogBestEffort(ctx context.Context, op string, ex Execer, query string, args ...any) {
	if _, err := ex.ExecContext(ctx, query, args...); err != nil {
		slog.WarnContext(ctx, "best-effort db op failed", "op", op, "err", err)
	}
}
