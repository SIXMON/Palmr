// Schema management via pressly/goose.
//
// Migrations live in ./migrations as `NNNN_name.sql` files, embedded
// into the binary at build time. On every boot the server runs
// `goose.Up`, which applies any migration not yet recorded in the
// `goose_db_version` tracking table.
//
// Adopting a pre-existing database:
//
//   When a Palmr instance was bootstrapped by Prisma (legacy Node
//   backend) or by the first revision of the Go backend (no goose),
//   the goose_db_version table is missing. On first run, goose creates
//   it, applies 0001_init.sql — which uses `CREATE TABLE IF NOT
//   EXISTS` and `CREATE INDEX IF NOT EXISTS` everywhere — and marks
//   the migration as applied. From then on, additional migrations are
//   picked up normally.
//
// Adding a future migration:
//
//   1. Pick the next number, e.g. 0002_add_user_locale.sql
//   2. Author the file with goose's annotations:
//
//          -- +goose Up
//          ALTER TABLE users ADD COLUMN locale TEXT;
//
//          -- +goose Down
//          ALTER TABLE users DROP COLUMN locale;
//
//   3. Rebuild — embed picks the file up automatically; the next boot
//      applies it.
package db

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// EnsureSchema applies every pending migration and seeds the
// app_configs table when it's empty.
func EnsureSchema(ctx context.Context, conn *sqlx.DB, dataDir string) error {
	if err := os.MkdirAll(filepath.Join(dataDir, "prisma"), 0o755); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}

	goose.SetBaseFS(migrationsFS)
	goose.SetLogger(goose.NopLogger()) // server emits its own structured logs
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, conn.DB, "migrations"); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	// Seed app_configs only when empty.
	var n int
	if err := conn.GetContext(ctx, &n, `SELECT COUNT(*) FROM app_configs`); err != nil {
		return fmt.Errorf("count configs: %w", err)
	}
	if n > 0 {
		return nil
	}
	return seedConfigs(ctx, conn)
}

type seedRow struct {
	Key, Value, Type, Group string
}

// defaults are the values seed.js writes on first boot.
var defaults = []seedRow{
	{Key: "appName", Value: "Palmr. ", Type: "string", Group: "general"},
	{Key: "showHomePage", Value: "true", Type: "boolean", Group: "general"},
	{Key: "hideVersion", Value: "false", Type: "boolean", Group: "general"},
	{Key: "appDescription", Value: "Secure and simple file sharing - Your personal cloud", Type: "string", Group: "general"},
	{Key: "appLogo", Value: "", Type: "string", Group: "general"},
	{Key: "firstUserAccess", Value: "true", Type: "boolean", Group: "general"},
	{Key: "maxFileSize", Value: "1073741824", Type: "bigint", Group: "storage"},
	{Key: "maxTotalStoragePerUser", Value: "10737418240", Type: "bigint", Group: "storage"},
	// Note: jwtSecret is intentionally NOT seeded — the runtime reads
	// the JWT_SECRET env var. A DB row would have no effect and the
	// admin settings UI would render it as an editable secret.
	{Key: "maxLoginAttempts", Value: "5", Type: "number", Group: "security"},
	{Key: "loginBlockDuration", Value: "600", Type: "number", Group: "security"},
	{Key: "passwordMinLength", Value: "8", Type: "number", Group: "security"},
	{Key: "passwordAuthEnabled", Value: "true", Type: "boolean", Group: "security"},
	{Key: "passwordResetTokenExpiration", Value: "3600", Type: "number", Group: "security"},
	{Key: "smtpEnabled", Value: "false", Type: "boolean", Group: "email"},
	{Key: "smtpHost", Value: "smtp.gmail.com", Type: "string", Group: "email"},
	{Key: "smtpPort", Value: "587", Type: "number", Group: "email"},
	{Key: "smtpUser", Value: "your-email@gmail.com", Type: "string", Group: "email"},
	{Key: "smtpPass", Value: "your-app-specific-password", Type: "string", Group: "email"},
	{Key: "smtpFromName", Value: "Palmr", Type: "string", Group: "email"},
	{Key: "smtpFromEmail", Value: "noreply@palmr.app", Type: "string", Group: "email"},
	{Key: "smtpSecure", Value: "auto", Type: "string", Group: "email"},
	{Key: "smtpNoAuth", Value: "false", Type: "boolean", Group: "email"},
	{Key: "smtpTrustSelfSigned", Value: "false", Type: "boolean", Group: "email"},
	{Key: "authProvidersEnabled", Value: "true", Type: "boolean", Group: "auth-providers"},
	{Key: "serverUrl", Value: "http://localhost:3333", Type: "string", Group: "general"},
}

func seedConfigs(ctx context.Context, conn *sqlx.DB) error {
	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	for _, r := range defaults {
		val := r.Value
		if val == "__RANDOM__" {
			b := make([]byte, 64)
			if _, err := rand.Read(b); err != nil {
				return fmt.Errorf("random: %w", err)
			}
			val = hex.EncodeToString(b)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_configs (id, key, value, "type", "group", isSystem, createdAt, updatedAt)
			VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			uuid.NewString(), r.Key, val, r.Type, r.Group); err != nil {
			return fmt.Errorf("seed %s: %w", r.Key, err)
		}
	}
	return tx.Commit()
}
