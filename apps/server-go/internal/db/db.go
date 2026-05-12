// Package db opens the SQLite database used by the legacy Node backend
// and exposes it through sqlx.
//
// The schema is owned by Prisma (apps/server/prisma/schema.prisma); we
// reuse the same .db file unchanged. This avoids any migration during
// the Go port — switching backends is a single docker-compose change.
//
// The driver is `modernc.org/sqlite`, a pure-Go SQLite implementation,
// chosen because we ship the binary in a `FROM scratch` image (no libc,
// no CGO toolchain).
package db

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// Open returns a connected sqlx.DB pointing at the Prisma-managed
// palmr.db file under dataDir. Caller owns Close.
func Open(ctx context.Context, dataDir string) (*sqlx.DB, error) {
	path := filepath.Join(dataDir, "prisma", "palmr.db")

	// modernc/sqlite uses the URI form. Flags chosen to match the
	// behaviour of the Prisma client:
	//   _pragma=journal_mode(WAL)       — concurrent reads
	//   _pragma=busy_timeout(5000)      — retry briefly on lock
	//   _pragma=foreign_keys(ON)        — enforce FKs (off by default!)
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)",
		path,
	)

	conn, err := sqlx.ConnectContext(ctx, "sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite at %s: %w", path, err)
	}

	// SQLite is single-writer; one connection for writes is enough.
	// Multiple readers can be served from prepared-statement pool though.
	conn.SetMaxOpenConns(8)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(30 * time.Minute)

	return conn, nil
}
