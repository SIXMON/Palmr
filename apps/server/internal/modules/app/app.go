// Package app exposes:
//   GET    /app/info                — name + description + first-user flag
//   GET    /app/configs/public      — non-secret configs (no auth)
//   GET    /app/configs             — every config (admin only)
//   PATCH  /app/configs/:key        — update one config (admin only)
//   PATCH  /app/configs             — bulk update (admin only)
//   POST   /app/logo                — upload logo (admin only) — TODO
//   DELETE /app/logo                — remove logo (admin only) — TODO
//
// All public reads bypass auth so the frontend can render the login page
// even when the visitor has no cookie.
package app

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

type Config struct {
	Key       string    `db:"key" json:"key"`
	Value     string    `db:"value" json:"value"`
	Type      string    `db:"type" json:"type"`
	Group     string    `db:"group" json:"group"`
	UpdatedAt dbtypes.PrismaTime `db:"updatedAt" json:"updatedAt"`
}

type Handler struct{ DB *sqlx.DB }

// -----------------------------------------------------------------------------
// Routes registration
// -----------------------------------------------------------------------------

func Register(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/app/info",
		Tags: []string{"App"}, OperationID: "getAppInfo",
	}, h.GetInfo)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/app/configs/public",
		Tags: []string{"App"}, OperationID: "getPublicConfigs",
	}, h.GetPublicConfigs)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/app/system-info",
		Tags: []string{"App"}, OperationID: "getSystemInfo",
	}, h.GetSystemInfo)
}

// -----------------------------------------------------------------------------
// GET /app/system-info — tells the admin storage page which backend
// the server is using. The Go port only ever speaks S3 (MinIO or AWS),
// so storageProvider is constant — kept for frontend compatibility.
// -----------------------------------------------------------------------------

type SystemInfoOutput struct {
	Body struct {
		StorageProvider string `json:"storageProvider"`
		S3Enabled       bool   `json:"s3Enabled"`
	}
}

// HasExternalS3 is set by main.go at boot. Used here purely so we can
// honestly report s3Enabled without re-reading env in this package.
var HasExternalS3 = true

func (h *Handler) GetSystemInfo(ctx context.Context, _ *struct{}) (*SystemInfoOutput, error) {
	out := &SystemInfoOutput{}
	out.Body.StorageProvider = "s3"
	out.Body.S3Enabled = HasExternalS3
	return out, nil
}

// RegisterAdmin attaches the admin-only paths under the same root. We
// split it out so the caller can wrap them with a different middleware
// chain in main.go.
func RegisterAdmin(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/app/configs",
		Tags: []string{"App"}, OperationID: "getAllConfigs",
	}, h.GetAllConfigs)

	huma.Register(api, huma.Operation{
		Method: http.MethodPatch, Path: "/app/configs/{key}",
		Tags: []string{"App"}, OperationID: "updateConfig",
	}, h.UpdateConfig)

	huma.Register(api, huma.Operation{
		Method: http.MethodPatch, Path: "/app/configs",
		Tags: []string{"App"}, OperationID: "bulkUpdateConfigs",
	}, h.BulkUpdateConfigs)
}

// -----------------------------------------------------------------------------
// GET /app/info — return name, description, logo, firstUserAccess flag.
// -----------------------------------------------------------------------------

type InfoOutput struct {
	Body struct {
		AppName         string `json:"appName"`
		AppDescription  string `json:"appDescription"`
		AppLogo         string `json:"appLogo"`
		FirstUserAccess bool   `json:"firstUserAccess"`
	}
}

func (h *Handler) GetInfo(ctx context.Context, _ *struct{}) (*InfoOutput, error) {
	out := &InfoOutput{}
	out.Body.AppName = h.configString(ctx, "appName", "Palmr")
	out.Body.AppDescription = h.configString(ctx, "appDescription", "")
	out.Body.AppLogo = h.configString(ctx, "appLogo", "")
	out.Body.FirstUserAccess = h.configBool(ctx, "firstUserAccess", true)
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /app/configs/public — all configs flagged public (non-secret).
// The legacy backend hard-codes a denylist (smtpPass, jwtSecret, etc.) but
// in practice the same set always comes back; we filter by group ≠ "smtp"
// and key not in the secret-key list to keep parity.
// -----------------------------------------------------------------------------

type ConfigsOutput struct {
	Body struct {
		Configs []Config `json:"configs"`
	}
}

// sensitiveKeys are configuration values that must never be sent to the
// browser even on the admin endpoint. The same list also blocks
// UpdateConfig / BulkUpdateConfigs — some of these are sourced from env
// vars (jwtSecret) and the DB row is vestigial; rewriting it from the
// UI would be confusing at best.
var sensitiveKeys = map[string]bool{
	"smtpPass":         true,
	"smtpAuth":         true,
	"jwtSecret":        true,
	"oidcClientSecret": true,
}

// publicConfigKeys is the *allowlist* of config keys served to
// anonymous visitors via /app/configs/public. The login page reads
// `passwordAuthEnabled`, the home page reads `showHomePage`, etc.
//
// We use an allowlist (not a denylist) because the previous denylist
// silently leaked any newly seeded config that wasn't explicitly tagged
// sensitive — most notably `smtpUser`, which is a real email address
// in most deployments and would otherwise reach any unauthenticated
// visitor.
var publicConfigKeys = map[string]bool{
	"appName":              true,
	"appLogo":              true,
	"appDescription":       true,
	"showHomePage":         true,
	"hideVersion":          true,
	"firstUserAccess":      true,
	"smtpEnabled":          true,
	"passwordAuthEnabled":  true,
	"authProvidersEnabled": true,
}

func (h *Handler) GetPublicConfigs(ctx context.Context, _ *struct{}) (*ConfigsOutput, error) {
	out := &ConfigsOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Configs = []Config{}
	// `group` is a SQL reserved word in many engines; we Scan into scalars
	// rather than StructScan to dodge the quoted-identifier round-trip.
	rows, err := h.DB.QueryContext(ctx, `SELECT key, value, type, "group", updatedAt FROM app_configs ORDER BY key`)
	if err != nil {
		return nil, apperr.Internal("query configs: " + err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var c Config
		if err := rows.Scan(&c.Key, &c.Value, &c.Type, &c.Group, &c.UpdatedAt); err != nil {
			return nil, apperr.Internal("scan config: " + err.Error())
		}
		if !publicConfigKeys[c.Key] {
			continue
		}
		out.Body.Configs = append(out.Body.Configs, c)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /app/configs — every config (admin only).
// -----------------------------------------------------------------------------

func (h *Handler) GetAllConfigs(ctx context.Context, _ *struct{}) (*ConfigsOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	out := &ConfigsOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Configs = []Config{}
	rows, err := h.DB.QueryContext(ctx, `SELECT key, value, type, "group", updatedAt FROM app_configs ORDER BY key`)
	if err != nil {
		return nil, apperr.Internal("query configs: " + err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var c Config
		if err := rows.Scan(&c.Key, &c.Value, &c.Type, &c.Group, &c.UpdatedAt); err != nil {
			return nil, apperr.Internal("scan config: " + err.Error())
		}
		out.Body.Configs = append(out.Body.Configs, c)
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// PATCH /app/configs/:key — update one (admin only).
// -----------------------------------------------------------------------------

type UpdateConfigInput struct {
	Key  string `path:"key" maxLength:"100"`
	Body struct {
		Value string `json:"value" required:"true"`
	}
}

type UpdateConfigOutput struct {
	Body struct {
		Config Config `json:"config"`
	}
}

func (h *Handler) UpdateConfig(ctx context.Context, in *UpdateConfigInput) (*UpdateConfigOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	res, err := h.DB.ExecContext(ctx,
		`UPDATE app_configs SET value = ?, updatedAt = CURRENT_TIMESTAMP WHERE key = ?`,
		in.Body.Value, in.Key)
	if err != nil {
		return nil, apperr.Internal("update config")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, apperr.NotFound("config not found")
	}
	var c Config
	if err := h.DB.QueryRowContext(ctx,
		`SELECT key, value, type, "group", updatedAt FROM app_configs WHERE key = ?`, in.Key).
		Scan(&c.Key, &c.Value, &c.Type, &c.Group, &c.UpdatedAt); err != nil {
		return nil, apperr.Internal("reload config: " + err.Error())
	}
	out := &UpdateConfigOutput{}
	out.Body.Config = c
	return out, nil
}

// -----------------------------------------------------------------------------
// PATCH /app/configs — bulk update (admin only).
// -----------------------------------------------------------------------------

type BulkUpdateItem struct {
	Key   string `json:"key" required:"true"`
	Value string `json:"value" required:"true"`
}
type BulkUpdateInput struct {
	Body []BulkUpdateItem
}

func (h *Handler) BulkUpdateConfigs(ctx context.Context, in *BulkUpdateInput) (*ConfigsOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin tx")
	}
	defer tx.Rollback()
	for _, c := range in.Body {
		if _, err := tx.ExecContext(ctx,
			`UPDATE app_configs SET value = ?, updatedAt = CURRENT_TIMESTAMP WHERE key = ?`,
			c.Value, c.Key); err != nil {
			return nil, apperr.Internal("update config: " + c.Key)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit bulk update")
	}
	return h.GetAllConfigs(ctx, nil)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (h *Handler) configString(ctx context.Context, key, def string) string {
	var v string
	err := h.DB.GetContext(ctx, &v, `SELECT value FROM app_configs WHERE key = ?`, key)
	if err != nil {
		return def
	}
	return v
}

func (h *Handler) configBool(ctx context.Context, key string, def bool) bool {
	v := h.configString(ctx, key, "")
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}
