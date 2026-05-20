// Package share owns /shares and /shares/alias/:alias.
//
// Authenticated endpoints:
//   POST   /shares                       create
//   GET    /shares/me                    list mine
//   GET    /shares/{shareId}             details (owner)
//   PUT    /shares                       update (rename, expiration, maxViews)
//   DELETE /shares/{id}                  delete
//   PATCH  /shares/{shareId}/password    set/clear password
//   POST   /shares/{shareId}/items       add files/folders
//   DELETE /shares/{shareId}/items       remove files/folders
//   POST   /shares/{shareId}/recipients  add emails
//   DELETE /shares/{shareId}/recipients  remove emails
//   POST   /shares/{shareId}/alias       create custom alias
//   POST   /shares/{shareId}/notify      send link to recipients
//
// Public endpoints:
//   GET    /shares/alias/{alias}             load by alias (password gated)
//   GET    /shares/alias/{alias}/metadata    OpenGraph metadata
package share

import (
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
	"github.com/sixmon/palmr/apps/server/internal/storage"
)

// Opaque error body for handler paths that don't return a typed
// huma response. Three call-sites in ServeDownload feed this to
// http.Error after slog'ing the real reason — collapsing the literal
// silences sonar S1192 and prevents the strings from drifting.
const errInternalMsg = "internal error"

type Share struct {
	ID          string     `db:"id"          json:"id"`
	Name        *string    `db:"name"        json:"name"`
	Description *string    `db:"description" json:"description"`
	Expiration  *dbtypes.PrismaTime `db:"expiration"  json:"expiration"`
	Views       int        `db:"views"       json:"views"`
	CreatedAt   dbtypes.PrismaTime  `db:"createdAt"   json:"createdAt"`
	UpdatedAt   dbtypes.PrismaTime  `db:"updatedAt"   json:"updatedAt"`
	CreatorID   string     `db:"creatorId"   json:"creatorId"`
	SecurityID  string     `db:"securityId"  json:"-"`
}

type ShareSecurity struct {
	Password *string `db:"password"`
	MaxViews *int    `db:"maxViews"`
}

type FileSummary struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description *string           `json:"description"`
	Extension   string            `json:"extension"`
	Size        dbtypes.BigIntStr `json:"size"`
	ObjectName  string            `json:"objectName"`
	// UserID is omitempty so the anonymous public-share path can drop
	// it (the public alias view clears the field before append). Owner
	// views always carry a real value. Without dropping this, an
	// anonymous visitor with one share alias can enumerate the
	// creator's other shares via the shared userId.
	UserID    string  `json:"userId,omitempty"`
	FolderID  *string `json:"folderId"`
	CreatedAt string  `json:"createdAt"`
	UpdatedAt string  `json:"updatedAt"`
}

type FolderSummary struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	ParentID    *string `json:"parentId"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

type Handler struct {
	DB *sqlx.DB
	// S3 is optional — only the /shares/alias/{alias}/download
	// endpoint needs it (to presign single-file URLs and to read
	// objects for the multi-file zip stream). The legacy JSON
	// endpoints work without it, so leaving it nil is OK for
	// hosted-only deployments.
	S3 *storage.S3

	// pwThrottle rate-limits share-password attempts per shareID. We
	// reuse maxLoginAttempts + loginBlockDuration from app_configs so
	// the admin doesn't get a third knob — the throttle is read each
	// request through pwThrottleConfig.
	//
	// Trade-off: keyed by shareID, so one attacker can lock everyone
	// out of a popular shared file for the duration of the block
	// window. That's intentional — the alternative (per-IP) is fragile
	// behind CDN/CGNAT, and the realistic mitigation for that DoS is
	// rate-limiting at the proxy.
	pwThrottle *shareThrottle

	// dlGate caps the number of in-flight downloads per share so a
	// single share can't be used as a bandwidth-amplification target
	// (M-DL1). Process-local; defaults to maxConcurrentDownloads. The
	// authoritative DoS protection still belongs at the reverse proxy
	// (limit_conn, fail2ban) — this is a backstop so one popular
	// share can't starve all other shares.
	dlGate *downloadGate
}

// New is what /cmd/server wires up. It exists so the throttle gets
// initialised — the zero-value Handler had no failure map, so a direct
// struct literal would nil-panic on first attempt. Existing literals
// that still set Handler{DB: ...} keep working because we lazy-init in
// pwThrottleHandle, but New is the recommended path going forward.
func New(db *sqlx.DB, s3 *storage.S3) *Handler {
	return &Handler{
		DB:         db,
		S3:         s3,
		pwThrottle: newShareThrottle(),
		dlGate:     newDownloadGate(maxConcurrentDownloadsPerShare),
	}
}

// shareThrottle is an in-memory sliding-window failure counter keyed
// by shareID. Lives for the process lifetime — restarting the server
// wipes the counters, which is fine: a brute-forcer would just lose
// their progress.
type shareThrottle struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newShareThrottle() *shareThrottle {
	return &shareThrottle{failures: map[string][]time.Time{}}
}

// blockedFor reports how long the caller must back off for, or 0 if
// they can attempt now. We drop timestamps older than `window` while
// we're holding the lock, so the map can't grow unbounded.
func (t *shareThrottle) blockedFor(shareID string, maxAttempts int, window time.Duration) time.Duration {
	if maxAttempts <= 0 || window <= 0 {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-window)
	prev := t.failures[shareID]
	fresh := prev[:0]
	for _, ts := range prev {
		if ts.After(cutoff) {
			fresh = append(fresh, ts)
		}
	}
	if len(fresh) == 0 {
		delete(t.failures, shareID)
	} else {
		t.failures[shareID] = fresh
	}
	if len(fresh) < maxAttempts {
		return 0
	}
	return time.Until(fresh[0].Add(window))
}

func (t *shareThrottle) recordFailure(shareID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures[shareID] = append(t.failures[shareID], time.Now())
}

func (t *shareThrottle) reset(shareID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, shareID)
}

// pwThrottleHandle returns the live throttle, allocating a fresh one
// on first use if the caller used the bare Handler{} literal. Keeps
// the constructor optional.
func (h *Handler) pwThrottleHandle() *shareThrottle {
	if h.pwThrottle == nil {
		h.pwThrottle = newShareThrottle()
	}
	return h.pwThrottle
}

func (h *Handler) pwThrottleConfig(ctx context.Context) (maxAttempts int, blockSeconds int) {
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

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"Share"}, OperationID: id}
	}
	// Public
	huma.Register(api, op(http.MethodGet, "/shares/alias/{alias}", "getShareByAlias"), h.GetByAlias)
	huma.Register(api, op(http.MethodGet, "/shares/alias/{alias}/metadata", "getShareMetadata"), h.GetAliasMetadata)

	// Authenticated
	huma.Register(api, op(http.MethodPost, "/shares", "createShare"), h.Create)
	huma.Register(api, op(http.MethodGet, "/shares/me", "listMyShares"), h.ListMine)
	huma.Register(api, op(http.MethodGet, "/shares/{shareId}", "getShare"), h.Get)
	huma.Register(api, op(http.MethodPut, "/shares", "updateShare"), h.Update)
	huma.Register(api, op(http.MethodDelete, "/shares/{id}", "deleteShare"), h.Delete)
	huma.Register(api, op(http.MethodPatch, "/shares/{shareId}/password", "updateSharePassword"), h.SetPassword)
	huma.Register(api, op(http.MethodPost, "/shares/{shareId}/items", "addShareItems"), h.AddItems)
	huma.Register(api, op(http.MethodDelete, "/shares/{shareId}/items", "removeShareItems"), h.RemoveItems)
	huma.Register(api, op(http.MethodPost, "/shares/{shareId}/recipients", "addRecipients"), h.AddRecipients)
	huma.Register(api, op(http.MethodDelete, "/shares/{shareId}/recipients", "removeRecipients"), h.RemoveRecipients)
	huma.Register(api, op(http.MethodPost, "/shares/{shareId}/alias", "createShareAlias"), h.CreateAlias)
	huma.Register(api, op(http.MethodPost, "/shares/{shareId}/notify", "notifyRecipients"), h.Notify)
}

// -----------------------------------------------------------------------------
// POST /shares
// -----------------------------------------------------------------------------

type ShareCreateInput struct {
	Body struct {
		Name        *string  `json:"name,omitempty"`
		Description *string  `json:"description,omitempty"`
		Expiration  *string  `json:"expiration,omitempty" format:"date-time"`
		Password    *string  `json:"password,omitempty"`
		MaxViews    *int     `json:"maxViews,omitempty"`
		Files       []string `json:"files,omitempty"`
		Folders     []string `json:"folders,omitempty"`
		Recipients  []string `json:"recipients,omitempty"`
	}
}

type ShareCreateOutput struct {
	Body struct {
		Share publicView `json:"share"`
	}
}

func (h *Handler) Create(ctx context.Context, in *ShareCreateInput) (*ShareCreateOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if len(in.Body.Files) == 0 && len(in.Body.Folders) == 0 {
		return nil, apperr.BadRequest("at least one file or folder is required")
	}
	hashedPwd := (*string)(nil)
	if in.Body.Password != nil && *in.Body.Password != "" {
		h, err := auth.HashPassword(*in.Body.Password, 12)
		if err != nil {
			return nil, apperr.BadRequest(err.Error())
		}
		hashedPwd = &h
	}

	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin")
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	secID := uuid.NewString()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO share_security (id, password, maxViews, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
		secID, hashedPwd, in.Body.MaxViews, now, now); err != nil {
		return nil, apperr.Internal("create security: " + err.Error())
	}

	id := uuid.NewString()
	var exp *time.Time
	if in.Body.Expiration != nil {
		if t, err := time.Parse(time.RFC3339, *in.Body.Expiration); err == nil {
			exp = &t
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO shares (id, name, description, expiration, views, createdAt, updatedAt, creatorId, securityId)
		 VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		id, in.Body.Name, in.Body.Description, exp, now, now, uc.UserID, secID); err != nil {
		return nil, apperr.Internal("create share: " + err.Error())
	}

	// Attach files (M2M table: _ShareFiles). SECURITY: the IDs come
	// from the request body — without an ownership check the caller
	// could attach someone else's file and then make it publicly
	// downloadable via the share alias.
	for _, fid := range in.Body.Files {
		if fid == "" {
			continue
		}
		if err := assertFileOwnedBy(ctx, tx, fid, uc.UserID); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _ShareFiles (A, B) VALUES (?, ?)`, fid, id); err != nil {
			return nil, apperr.Internal("attach file: " + err.Error())
		}
	}
	for _, fid := range in.Body.Folders {
		if fid == "" {
			continue
		}
		if err := assertFolderOwnedBy(ctx, tx, fid, uc.UserID); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _ShareFolders (A, B) VALUES (?, ?)`, fid, id); err != nil {
			return nil, apperr.Internal("attach folder: " + err.Error())
		}
	}
	for _, email := range in.Body.Recipients {
		if email = strings.TrimSpace(strings.ToLower(email)); email == "" {
			continue
		}
		rid := uuid.NewString()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO share_recipients (id, email, shareId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
			rid, email, id, now, now); err != nil {
			return nil, apperr.Internal("attach recipient: " + err.Error())
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit: " + err.Error())
	}

	v, err := h.fullView(ctx, id)
	if err != nil {
		return nil, apperr.Internal("reload: " + err.Error())
	}
	out := &ShareCreateOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /shares/me
// -----------------------------------------------------------------------------

type ShareListOutput struct {
	Body struct {
		Shares []publicView `json:"shares"`
	}
}

func (h *Handler) ListMine(ctx context.Context, _ *struct{}) (*ShareListOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	// Single SELECT for the row order, then batch-load every relation in
	// O(1) queries (security, recipients, files, folders, aliases) →
	// constant round-trips regardless of how many shares the user owns.
	var ids []string
	if err := h.DB.SelectContext(ctx, &ids,
		`SELECT id FROM shares WHERE creatorId = ? ORDER BY createdAt DESC`, uc.UserID); err != nil {
		return nil, apperr.Internal("list shares")
	}
	out := &ShareListOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Shares = []publicView{}
	if len(ids) == 0 {
		return out, nil
	}
	views, err := h.fullViewMany(ctx, ids, true /* owner view */)
	if err != nil {
		return nil, apperr.Internal("load shares")
	}
	out.Body.Shares = views
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /shares/{shareId}
// -----------------------------------------------------------------------------

type ShareGetInput struct{ ShareID string `path:"shareId"` }
type ShareGetOutput struct{ Body struct{ Share publicView `json:"share"` } }

func (h *Handler) Get(ctx context.Context, in *ShareGetInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	v, err := h.fullView(ctx, in.ShareID)
	if err != nil {
		return nil, apperr.NotFound("share not found")
	}
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// PUT /shares — update
// -----------------------------------------------------------------------------

type ShareUpdateInput struct {
	Body struct {
		ID          string   `json:"id" required:"true"`
		Name        *string  `json:"name,omitempty"`
		Description *string  `json:"description,omitempty"`
		Expiration  *string  `json:"expiration,omitempty" format:"date-time"`
		MaxViews    *int     `json:"maxViews,omitempty"`
		Password    *string  `json:"password,omitempty"`
		Recipients  []string `json:"recipients,omitempty"`
	}
}

func (h *Handler) Update(ctx context.Context, in *ShareUpdateInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.Body.ID, uc.UserID); err != nil {
		return nil, err
	}
	fields := []string{}
	args := []any{}
	if in.Body.Name != nil {
		fields = append(fields, "name = ?")
		args = append(args, *in.Body.Name)
	}
	if in.Body.Description != nil {
		fields = append(fields, "description = ?")
		args = append(args, *in.Body.Description)
	}
	if in.Body.Expiration != nil {
		if t, err := time.Parse(time.RFC3339, *in.Body.Expiration); err == nil {
			fields = append(fields, "expiration = ?")
			args = append(args, t)
		}
	}
	if len(fields) > 0 {
		fields = append(fields, "updatedAt = CURRENT_TIMESTAMP")
		args = append(args, in.Body.ID)
		q := "UPDATE shares SET " + strings.Join(fields, ", ") + " WHERE id = ?"
		if _, err := h.DB.ExecContext(ctx, q, args...); err != nil {
			return nil, apperr.Internal("update share")
		}
	}
	if in.Body.MaxViews != nil {
		if _, err := h.DB.ExecContext(ctx,
			`UPDATE share_security SET maxViews = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = (SELECT securityId FROM shares WHERE id = ?)`,
			*in.Body.MaxViews, in.Body.ID); err != nil {
			return nil, apperr.Internal("update maxViews")
		}
	}
	if in.Body.Password != nil {
		var hashed *string
		if *in.Body.Password != "" {
			hp, err := auth.HashPassword(*in.Body.Password, 12)
			if err != nil {
				return nil, apperr.BadRequest(err.Error())
			}
			hashed = &hp
		}
		if _, err := h.DB.ExecContext(ctx,
			`UPDATE share_security SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = (SELECT securityId FROM shares WHERE id = ?)`,
			hashed, in.Body.ID); err != nil {
			return nil, apperr.Internal("update password")
		}
	}
	if in.Body.Recipients != nil {
		// Full replacement: wipe and re-add. Cheaper than diffing for a list typically <50 entries.
		dbtypes.LogBestEffort(ctx, "share.share.delete.from.share_recipients.where", h.DB, `DELETE FROM share_recipients WHERE shareId = ?`, in.Body.ID)
		now := time.Now().UTC()
		for _, e := range in.Body.Recipients {
			e = strings.TrimSpace(strings.ToLower(e))
			if e == "" {
				continue
			}
			dbtypes.LogBestEffort(ctx, "share.update.insert_recipient", h.DB,
				`INSERT INTO share_recipients (id, email, shareId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
				uuid.NewString(), e, in.Body.ID, now, now)
		}
	}
	v, _ := h.fullView(ctx, in.Body.ID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// DELETE /shares/{id}
// -----------------------------------------------------------------------------

type ShareDeleteInput struct{ ID string `path:"id"` }
type ShareMsgOutput struct{ Body struct{ Message string `json:"message"` } }

func (h *Handler) Delete(ctx context.Context, in *ShareDeleteInput) (*ShareMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM shares WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete share")
	}
	out := &ShareMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

// -----------------------------------------------------------------------------
// PATCH /shares/{shareId}/password
// -----------------------------------------------------------------------------

type SharePasswordInput struct {
	ShareID string `path:"shareId"`
	Body    struct {
		Password *string `json:"password"`
	}
}

func (h *Handler) SetPassword(ctx context.Context, in *SharePasswordInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	hashed := (*string)(nil)
	if in.Body.Password != nil && *in.Body.Password != "" {
		h, err := auth.HashPassword(*in.Body.Password, 12)
		if err != nil {
			return nil, apperr.BadRequest(err.Error())
		}
		hashed = &h
	}
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE share_security SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = (SELECT securityId FROM shares WHERE id = ?)`,
		hashed, in.ShareID); err != nil {
		return nil, apperr.Internal("set password")
	}
	v, _ := h.fullView(ctx, in.ShareID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// POST/DELETE /shares/{shareId}/items
// -----------------------------------------------------------------------------

type ShareItemsInput struct {
	ShareID string `path:"shareId"`
	Body    struct {
		Files   []string `json:"files,omitempty"`
		Folders []string `json:"folders,omitempty"`
	}
}

func (h *Handler) AddItems(ctx context.Context, in *ShareItemsInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	// SECURITY: verify each id is owned by the caller before joining
	// it to the share. Without this, an owner of share A could attach
	// user B's files to A and expose them via A's public alias.
	for _, fid := range in.Body.Files {
		if fid == "" {
			continue
		}
		if err := assertFileOwnedBy(ctx, h.DB, fid, uc.UserID); err != nil {
			return nil, err
		}
		dbtypes.LogBestEffort(ctx, "share.attach_file", h.DB, `INSERT OR IGNORE INTO _ShareFiles (A, B) VALUES (?, ?)`, fid, in.ShareID)
	}
	for _, fid := range in.Body.Folders {
		if fid == "" {
			continue
		}
		if err := assertFolderOwnedBy(ctx, h.DB, fid, uc.UserID); err != nil {
			return nil, err
		}
		dbtypes.LogBestEffort(ctx, "share.attach_folder", h.DB, `INSERT OR IGNORE INTO _ShareFolders (A, B) VALUES (?, ?)`, fid, in.ShareID)
	}
	v, _ := h.fullView(ctx, in.ShareID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

func (h *Handler) RemoveItems(ctx context.Context, in *ShareItemsInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	for _, fid := range in.Body.Files {
		dbtypes.LogBestEffort(ctx, "share.share.delete.from._sharefiles.where", h.DB, `DELETE FROM _ShareFiles WHERE A = ? AND B = ?`, fid, in.ShareID)
	}
	for _, fid := range in.Body.Folders {
		dbtypes.LogBestEffort(ctx, "share.share.delete.from._sharefolders.where", h.DB, `DELETE FROM _ShareFolders WHERE A = ? AND B = ?`, fid, in.ShareID)
	}
	v, _ := h.fullView(ctx, in.ShareID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// POST/DELETE /shares/{shareId}/recipients
// -----------------------------------------------------------------------------

type ShareRecipientsInput struct {
	ShareID string `path:"shareId"`
	Body    struct {
		Emails []string `json:"emails" required:"true"`
	}
}

func (h *Handler) AddRecipients(ctx context.Context, in *ShareRecipientsInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, e := range in.Body.Emails {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		dbtypes.LogBestEffort(ctx, "share.recipients.add", h.DB,
			`INSERT INTO share_recipients (id, email, shareId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
			uuid.NewString(), e, in.ShareID, now, now)
	}
	v, _ := h.fullView(ctx, in.ShareID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

func (h *Handler) RemoveRecipients(ctx context.Context, in *ShareRecipientsInput) (*ShareGetOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	for _, e := range in.Body.Emails {
		dbtypes.LogBestEffort(ctx, "share.recipients.remove", h.DB,
			`DELETE FROM share_recipients WHERE shareId = ? AND email = ?`, in.ShareID, strings.ToLower(e))
	}
	v, _ := h.fullView(ctx, in.ShareID)
	out := &ShareGetOutput{}
	out.Body.Share = v
	return out, nil
}

// -----------------------------------------------------------------------------
// POST /shares/{shareId}/alias
// -----------------------------------------------------------------------------

type ShareAliasInput struct {
	ShareID string `path:"shareId"`
	Body    struct {
		Alias *string `json:"alias,omitempty"`
	}
}
// ShareAliasBody matches the frontend `ShareAlias` type — 5 fields.
// Earlier this only carried {alias, shareId}; the missing id/createdAt/
// updatedAt left consumers reading undefined.
type ShareAliasBody struct {
	ID        string `json:"id"`
	Alias     string `json:"alias"`
	ShareID   string `json:"shareId"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}
type ShareAliasOutput struct {
	Body struct {
		Alias ShareAliasBody `json:"alias"`
	}
}

func (h *Handler) CreateAlias(ctx context.Context, in *ShareAliasInput) (*ShareAliasOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	alias := ""
	if in.Body.Alias != nil && *in.Body.Alias != "" {
		alias = *in.Body.Alias
		if len(alias) < 8 {
			return nil, apperr.BadRequest("alias must be at least 8 characters")
		}
	} else {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		alias = hex.EncodeToString(b)
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(ctx,
		`INSERT INTO share_aliases (id, alias, shareId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
		id, alias, in.ShareID, now, now)
	if err != nil {
		return nil, apperr.Conflict("alias already taken or share already aliased")
	}
	stamp := now.Format(time.RFC3339)
	out := &ShareAliasOutput{}
	out.Body.Alias = ShareAliasBody{
		ID:        id,
		Alias:     alias,
		ShareID:   in.ShareID,
		CreatedAt: stamp,
		UpdatedAt: stamp,
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// POST /shares/{shareId}/notify  — placeholder, see email module TODO.
// -----------------------------------------------------------------------------

type NotifyInput struct {
	ShareID string `path:"shareId"`
	Body    struct {
		ShareLink string `json:"shareLink" required:"true"`
	}
}

// NotifyOutput matches `NotifyRecipients200 { message, notifiedRecipients }`
// — the future success toast / UI listing will read the recipient array. We
// emit the recipients list from the DB so the frontend already gets the
// right shape even though the email worker isn't wired yet.
type NotifyOutput struct {
	Body struct {
		Message             string   `json:"message"`
		NotifiedRecipients  []string `json:"notifiedRecipients"`
	}
}

func (h *Handler) Notify(ctx context.Context, in *NotifyInput) (*NotifyOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ShareID, uc.UserID); err != nil {
		return nil, err
	}
	// Resolve the recipient list — even though the email worker isn't
	// wired yet, the frontend wants to display "notified N people".
	recipients := []string{}
	_ = h.DB.SelectContext(ctx, &recipients,
		`SELECT email FROM share_recipients WHERE shareId = ? ORDER BY email`, in.ShareID)
	// TODO: hand off to the email service once email module is wired up.
	out := &NotifyOutput{}
	out.Body.Message = "notifications queued (email service not yet wired)"
	out.Body.NotifiedRecipients = recipients
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /shares/alias/{alias} — public, password-gated
// -----------------------------------------------------------------------------

type publicView struct {
	ID          string          `json:"id"`
	Name        *string         `json:"name"`
	Description *string         `json:"description"`
	Expiration  *time.Time      `json:"expiration"`
	Views       int             `json:"views"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	CreatorID   string          `json:"creatorId,omitempty"`
	Security    securityView    `json:"security"`
	Files       []FileSummary   `json:"files"`
	Folders     []FolderSummary `json:"folders"`
	// Recipients is mandatory `T[]` on the frontend (`ShareRecipient[]`),
	// so it must always serialise as an array, never `null`. Public alias
	// views still receive an empty slice (not the owner-only list).
	Recipients []recipientView `json:"recipients"`
	Alias      *aliasView      `json:"alias"`
}

type securityView struct {
	MaxViews    *int `json:"maxViews"`
	HasPassword bool `json:"hasPassword"`
}

type recipientView struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type aliasView struct {
	ID        string `json:"id"`
	Alias     string `json:"alias"`
	ShareID   string `json:"shareId"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type ByAliasInput struct {
	Alias         string `path:"alias"`
	Password      string `query:"password"`
	HeaderPassword string `header:"X-Share-Password"`
}

type ByAliasOutput struct {
	Body struct {
		Share publicView `json:"share"`
	}
}

func (h *Handler) GetByAlias(ctx context.Context, in *ByAliasInput) (*ByAliasOutput, error) {
	var shareID string
	if err := h.DB.GetContext(ctx, &shareID,
		`SELECT shareId FROM share_aliases WHERE alias = ?`, in.Alias); err != nil {
		return nil, apperr.NotFound("alias not found")
	}

	var sec ShareSecurity
	_ = h.DB.GetContext(ctx, &sec,
		`SELECT sec.password, sec.maxViews
		 FROM share_security sec JOIN shares s ON s.securityId = sec.id WHERE s.id = ?`, shareID)

	pwd := in.HeaderPassword
	if pwd == "" {
		pwd = in.Password
	}
	if sec.Password != nil && *sec.Password != "" {
		// SECURITY: rate-limit before bcrypt. Without this, an
		// attacker could brute-force the share password at the speed
		// of HTTP requests (bcrypt cost 12 is ~250 ms but still
		// trivially parallel across many shares / connections). We
		// reuse the login-throttle config so the admin tunes one
		// knob; lockout is per-shareID (see Handler.pwThrottle docs
		// for the DoS trade-off).
		maxAttempts, blockSeconds := h.pwThrottleConfig(ctx)
		throttle := h.pwThrottleHandle()
		if blocked := throttle.blockedFor(shareID, maxAttempts, time.Duration(blockSeconds)*time.Second); blocked > 0 {
			return nil, apperr.Unauthorized(
				"too many failed password attempts; try again in " + blocked.Round(time.Second).String())
		}
		if pwd == "" {
			return nil, apperr.Unauthorized("Password required")
		}
		if !auth.VerifyPassword(pwd, *sec.Password) {
			throttle.recordFailure(shareID)
			return nil, apperr.Unauthorized("Invalid password")
		}
		// Success: wipe the counter so legitimate readers don't
		// inherit the attacker's failures.
		throttle.reset(shareID)
	}

	// max-views gate
	var views int
	_ = h.DB.GetContext(ctx, &views, `SELECT views FROM shares WHERE id = ?`, shareID)
	if sec.MaxViews != nil && views >= *sec.MaxViews {
		return nil, apperr.Gone("share has reached its max views")
	}

	// expiration gate
	var exp *time.Time
	_ = h.DB.GetContext(ctx, &exp, `SELECT expiration FROM shares WHERE id = ?`, shareID)
	if exp != nil && exp.Before(time.Now()) {
		return nil, apperr.Gone("share has expired")
	}

	// Increment views
	dbtypes.LogBestEffort(ctx, "share.share.update.shares.set.views", h.DB, `UPDATE shares SET views = views + 1 WHERE id = ?`, shareID)

	v, err := h.publicView(ctx, shareID)
	if err != nil {
		return nil, apperr.Internal("load share")
	}
	out := &ByAliasOutput{}
	out.Body.Share = v
	return out, nil
}

type ShareAliasMetaInput struct{ Alias string `path:"alias"` }

// ShareAliasMetaOutput includes file/folder counts so the public share's
// OpenGraph description can render copy like "N files shared" — see
// `apps/web/src/app/(shares)/s/[alias]/layout.tsx`. Without them the page
// falls back to a generic translated string.
type ShareAliasMetaOutput struct {
	Body struct {
		Name         *string `json:"name"`
		Description  *string `json:"description"`
		AppName      string  `json:"appName"`
		TotalFiles   int     `json:"totalFiles"`
		TotalFolders int     `json:"totalFolders"`
	}
}

func (h *Handler) GetAliasMetadata(ctx context.Context, in *ShareAliasMetaInput) (*ShareAliasMetaOutput, error) {
	out := &ShareAliasMetaOutput{}
	var shareID string
	row := h.DB.QueryRowContext(ctx, `
		SELECT s.id, s.name, s.description
		FROM shares s JOIN share_aliases sa ON sa.shareId = s.id
		WHERE sa.alias = ?`, in.Alias)
	_ = row.Scan(&shareID, &out.Body.Name, &out.Body.Description)
	if shareID != "" {
		// In the Prisma M2M join tables A is the related entity id
		// (file/folder) and B is the share id — see file:818, file:842.
		_ = h.DB.GetContext(ctx, &out.Body.TotalFiles,
			`SELECT COUNT(*) FROM _ShareFiles WHERE B = ?`, shareID)
		_ = h.DB.GetContext(ctx, &out.Body.TotalFolders,
			`SELECT COUNT(*) FROM _ShareFolders WHERE B = ?`, shareID)
	}
	_ = h.DB.GetContext(ctx, &out.Body.AppName, `SELECT value FROM app_configs WHERE key = 'appName'`)
	if out.Body.AppName == "" {
		out.Body.AppName = "Palmr"
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func (h *Handler) assertOwner(ctx context.Context, shareID, userID string) error {
	var owner string
	if err := h.DB.GetContext(ctx, &owner, `SELECT creatorId FROM shares WHERE id = ?`, shareID); err != nil {
		return apperr.NotFound("share not found")
	}
	if owner != userID {
		return apperr.Forbidden("not your share")
	}
	return nil
}

// dbExecutor is the subset of sqlx.{DB,Tx} we use in the two ownership
// helpers — lets the same code run inside a transaction during Create
// and on the bare DB during AddItems.
type dbExecutor interface {
	GetContext(ctx context.Context, dest any, query string, args ...any) error
}

// assertFileOwnedBy returns a Forbidden error if the file row exists
// but belongs to someone else; NotFound when no row matches the id.
// Used at every spot where the caller supplies a file id from a
// request body (share Create / AddItems).
func assertFileOwnedBy(ctx context.Context, ex dbExecutor, fileID, userID string) error {
	var owner string
	if err := ex.GetContext(ctx, &owner, `SELECT userId FROM files WHERE id = ?`, fileID); err != nil {
		return apperr.NotFound("file not found")
	}
	if owner != userID {
		return apperr.Forbidden("file not owned by caller")
	}
	return nil
}

// assertFolderOwnedBy mirrors assertFileOwnedBy for folder ids.
func assertFolderOwnedBy(ctx context.Context, ex dbExecutor, folderID, userID string) error {
	var owner string
	if err := ex.GetContext(ctx, &owner, `SELECT userId FROM folders WHERE id = ?`, folderID); err != nil {
		return apperr.NotFound("folder not found")
	}
	if owner != userID {
		return apperr.Forbidden("folder not owned by caller")
	}
	return nil
}

// fullViewMany is the batched cousin of fullView. It runs five SELECTs
// (one per relation table) regardless of how many shares are requested
// and assembles the result in Go, killing the N+1 round-trip pattern
// the single-id version creates when /shares/me has dozens of rows.
//
// `withRecipients` toggles the recipients fan-out — true for the owner
// view, false for public alias views (which already exclude recipients).
//
// Each relation has its own helper so this orchestrator stays simple
// (sonar S3776) — the per-step error handling and row-scan logic
// lives in fanInShare{Files,Folders,Aliases,Recipients}.
func (h *Handler) fullViewMany(ctx context.Context, ids []string, withRecipients bool) ([]publicView, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	views, err := h.loadSharesAndSecurity(ctx, ids)
	if err != nil {
		return nil, err
	}
	h.fanInShareFiles(ctx, ids, views)
	h.fanInShareFolders(ctx, ids, views)
	h.fanInShareAliases(ctx, ids, views)
	if withRecipients {
		h.fanInShareRecipients(ctx, ids, views)
	}
	// Preserve the requested order — caller already sorted by createdAt.
	out := make([]publicView, 0, len(ids))
	for _, id := range ids {
		if v, ok := views[id]; ok {
			out = append(out, *v)
		}
	}
	return out, nil
}

// loadSharesAndSecurity is step 1 of fullViewMany: pull the shares
// JOINed against their security row, returning a map keyed by id so
// the fan-in helpers can attach rows without an extra SELECT.
func (h *Handler) loadSharesAndSecurity(ctx context.Context, ids []string) (map[string]*publicView, error) {
	q, args, err := sqlx.In(`
		SELECT s.id, s.name, s.description, s.expiration, s.views, s.createdAt, s.updatedAt, s.creatorId,
		       sec.password, sec.maxViews
		FROM shares s JOIN share_security sec ON sec.id = s.securityId
		WHERE s.id IN (?)`, ids)
	if err != nil {
		return nil, err
	}
	rows, err := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	views := make(map[string]*publicView, len(ids))
	for rows.Next() {
		var (
			s        Share
			pwd      *string
			maxViews *int
		)
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.Expiration, &s.Views,
			&s.CreatedAt, &s.UpdatedAt, &s.CreatorID, &pwd, &maxViews); err != nil {
			return nil, err
		}
		var exp *time.Time
		if s.Expiration != nil {
			t := s.Expiration.Time
			exp = &t
		}
		views[s.ID] = &publicView{
			ID: s.ID, Name: s.Name, Description: s.Description,
			Expiration: exp, Views: s.Views,
			CreatedAt: s.CreatedAt.Time, UpdatedAt: s.UpdatedAt.Time,
			CreatorID: s.CreatorID,
			Security:  securityView{MaxViews: maxViews, HasPassword: pwd != nil && *pwd != ""},
			// Pre-initialise so empty results serialise as `[]`, not `null`.
			Files:      []FileSummary{},
			Folders:    []FolderSummary{},
			Recipients: []recipientView{},
		}
	}
	return views, nil
}

func (h *Handler) fanInShareFiles(ctx context.Context, ids []string, views map[string]*publicView) {
	q, args, err := sqlx.In(`
		SELECT sf.B, f.id, f.name, f.description, f.extension, f.size, f.objectName, f.userId, f.folderId, f.createdAt, f.updatedAt
		FROM _ShareFiles sf JOIN files f ON sf.A = f.id WHERE sf.B IN (?)`, ids)
	if err != nil {
		return
	}
	rows, err := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
	if err != nil || rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var shareID string
		var fs FileSummary
		var created, updated dbtypes.PrismaTime
		if err := rows.Scan(&shareID, &fs.ID, &fs.Name, &fs.Description, &fs.Extension, &fs.Size,
			&fs.ObjectName, &fs.UserID, &fs.FolderID, &created, &updated); err != nil {
			continue
		}
		fs.CreatedAt = created.Time.Format(time.RFC3339)
		fs.UpdatedAt = updated.Time.Format(time.RFC3339)
		if v, ok := views[shareID]; ok {
			v.Files = append(v.Files, fs)
		}
	}
}

func (h *Handler) fanInShareFolders(ctx context.Context, ids []string, views map[string]*publicView) {
	q, args, err := sqlx.In(`
		SELECT sf.B, f.id, f.name, f.description, f.parentId, f.createdAt, f.updatedAt
		FROM _ShareFolders sf JOIN folders f ON sf.A = f.id WHERE sf.B IN (?)`, ids)
	if err != nil {
		return
	}
	rows, err := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
	if err != nil || rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var shareID string
		var fs FolderSummary
		var created, updated dbtypes.PrismaTime
		if err := rows.Scan(&shareID, &fs.ID, &fs.Name, &fs.Description, &fs.ParentID, &created, &updated); err != nil {
			continue
		}
		fs.CreatedAt = created.Time.Format(time.RFC3339)
		fs.UpdatedAt = updated.Time.Format(time.RFC3339)
		if v, ok := views[shareID]; ok {
			v.Folders = append(v.Folders, fs)
		}
	}
}

func (h *Handler) fanInShareAliases(ctx context.Context, ids []string, views map[string]*publicView) {
	q, args, err := sqlx.In(`
		SELECT id, alias, shareId, createdAt, updatedAt FROM share_aliases WHERE shareId IN (?)`, ids)
	if err != nil {
		return
	}
	rows, err := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
	if err != nil || rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var av aliasView
		var created, updated dbtypes.PrismaTime
		if err := rows.Scan(&av.ID, &av.Alias, &av.ShareID, &created, &updated); err != nil {
			continue
		}
		av.CreatedAt = created.Time.Format(time.RFC3339)
		av.UpdatedAt = updated.Time.Format(time.RFC3339)
		if v, ok := views[av.ShareID]; ok {
			v.Alias = &av
		}
	}
}

func (h *Handler) fanInShareRecipients(ctx context.Context, ids []string, views map[string]*publicView) {
	q, args, err := sqlx.In(`
		SELECT shareId, id, email, createdAt, updatedAt FROM share_recipients WHERE shareId IN (?)`, ids)
	if err != nil {
		return
	}
	rows, err := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
	if err != nil || rows == nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var shareID string
		var r recipientView
		var created, updated dbtypes.PrismaTime
		if err := rows.Scan(&shareID, &r.ID, &r.Email, &created, &updated); err != nil {
			continue
		}
		r.CreatedAt = created.Time.Format(time.RFC3339)
		r.UpdatedAt = updated.Time.Format(time.RFC3339)
		if v, ok := views[shareID]; ok {
			v.Recipients = append(v.Recipients, r)
		}
	}
}

// fullView returns the owner view (with creatorId, recipients, objectName).
func (h *Handler) fullView(ctx context.Context, shareID string) (publicView, error) {
	v, err := h.publicView(ctx, shareID)
	if err != nil {
		return v, err
	}
	var creator string
	_ = h.DB.GetContext(ctx, &creator, `SELECT creatorId FROM shares WHERE id = ?`, shareID)
	v.CreatorID = creator

	rows, _ := h.DB.QueryxContext(ctx,
		`SELECT id, email, createdAt, updatedAt FROM share_recipients WHERE shareId = ?`, shareID)
	defer rows.Close()
	for rows.Next() {
		var r recipientView
		var created, updated dbtypes.PrismaTime
		_ = rows.Scan(&r.ID, &r.Email, &created, &updated)
		r.CreatedAt = created.Time.Format(time.RFC3339)
		r.UpdatedAt = updated.Time.Format(time.RFC3339)
		v.Recipients = append(v.Recipients, r)
	}
	return v, nil
}

// publicView returns the share-by-alias view (no creatorId, no recipients).
func (h *Handler) publicView(ctx context.Context, shareID string) (publicView, error) {
	var s Share
	if err := h.DB.GetContext(ctx, &s,
		`SELECT id, name, description, expiration, views, createdAt, updatedAt, creatorId, securityId
		 FROM shares WHERE id = ?`, shareID); err != nil {
		return publicView{}, err
	}
	var sec ShareSecurity
	_ = h.DB.GetContext(ctx, &sec, `SELECT password, maxViews FROM share_security WHERE id = ?`, s.SecurityID)

	var exp *time.Time
	if s.Expiration != nil {
		t := s.Expiration.Time
		exp = &t
	}
	v := publicView{
		ID: s.ID, Name: s.Name, Description: s.Description,
		Expiration: exp, Views: s.Views,
		CreatedAt: s.CreatedAt.Time, UpdatedAt: s.UpdatedAt.Time,
		Security: securityView{MaxViews: sec.MaxViews, HasPassword: sec.Password != nil && *sec.Password != ""},
		// Pre-initialise so empty results serialise as `[]`, not `null`.
		Files:      []FileSummary{},
		Folders:    []FolderSummary{},
		Recipients: []recipientView{},
	}

	// Files via M2M
	rowsF, _ := h.DB.QueryxContext(ctx, `
		SELECT f.id, f.name, f.description, f.extension, f.size, f.objectName, f.userId, f.folderId, f.createdAt, f.updatedAt
		FROM files f JOIN _ShareFiles sf ON sf.A = f.id WHERE sf.B = ?`, shareID)
	defer rowsF.Close()
	for rowsF.Next() {
		var fs FileSummary
		var created, updated dbtypes.PrismaTime
		_ = rowsF.Scan(&fs.ID, &fs.Name, &fs.Description, &fs.Extension, &fs.Size, &fs.ObjectName, &fs.UserID, &fs.FolderID, &created, &updated)
		fs.CreatedAt = created.Time.Format(time.RFC3339)
		fs.UpdatedAt = updated.Time.Format(time.RFC3339)
		// Strip the creator userId on the anonymous public-share path —
		// anonymous visitors don't need to know who owns the share.
		// FileSummary.UserID has `omitempty`, so an empty string drops
		// the field from the JSON entirely.
		fs.UserID = ""
		v.Files = append(v.Files, fs)
	}

	// Folders via M2M
	rowsG, _ := h.DB.QueryxContext(ctx, `
		SELECT f.id, f.name, f.description, f.parentId, f.createdAt, f.updatedAt
		FROM folders f JOIN _ShareFolders sf ON sf.A = f.id WHERE sf.B = ?`, shareID)
	defer rowsG.Close()
	for rowsG.Next() {
		var fs FolderSummary
		var created, updated dbtypes.PrismaTime
		_ = rowsG.Scan(&fs.ID, &fs.Name, &fs.Description, &fs.ParentID, &created, &updated)
		fs.CreatedAt = created.Time.Format(time.RFC3339)
		fs.UpdatedAt = updated.Time.Format(time.RFC3339)
		v.Folders = append(v.Folders, fs)
	}

	// alias
	row := h.DB.QueryRowContext(ctx,
		`SELECT id, alias, shareId, createdAt, updatedAt FROM share_aliases WHERE shareId = ?`, shareID)
	var av aliasView
	var aliasCreated, aliasUpdated dbtypes.PrismaTime
	if err := row.Scan(&av.ID, &av.Alias, &av.ShareID, &aliasCreated, &aliasUpdated); err == nil {
		av.CreatedAt = aliasCreated.Time.Format(time.RFC3339)
		av.UpdatedAt = aliasUpdated.Time.Format(time.RFC3339)
		v.Alias = &av
	}
	return v, nil
}

// -----------------------------------------------------------------------------
// Public download endpoint — `GET /shares/alias/{alias}/download`
//
// Designed for direct curl/wget access. nginx routes /s/{alias} to this
// handler when the client doesn't ask for HTML (Accept header check),
// so the same URL the user copy-pastes in the browser also works as
// `curl -L -o out.zip https://palmr/s/<alias>`.
//
// Password handling, in priority order:
//   1. `Authorization: Basic <base64(:password)>` — idiomatic curl
//      (`-u :secret`). The username portion is ignored.
//   2. `X-Share-Password: <password>` — what the SPA sends today.
// `?password=` is intentionally NOT accepted: query strings end up in
// proxy logs and browser history.
//
// Response shape:
//   - Wrong/missing password → 401 + `WWW-Authenticate: Basic realm=...`
//     so curl can re-prompt interactively and shell scripts can detect.
//   - Single file & no folders → 302 to a presigned S3 URL. RustFS
//     streams the bytes directly, zero backend bandwidth.
//   - Multi-file or any folder → on-the-fly zip via archive/zip.
//     Constant RAM; we read each S3 object into the zip writer's
//     stream as it goes. Folder hierarchy is preserved with relative
//     paths inside the archive.
//
// Throttling: shares the same per-shareID failure window as
// GetByAlias (M1), so brute-force across this endpoint and the SPA
// path is rate-limited as one bucket.
// -----------------------------------------------------------------------------

// RegisterPlain attaches the chi-native download endpoint. We can't
// use huma here because the response is either a 302 redirect or a
// streaming zip — neither fits huma's JSON-typed output model. Both
// GET and HEAD are registered: some clients (wget --spider, some
// backup tools) probe with HEAD before downloading.
func (h *Handler) RegisterPlain(r chi.Router) {
	r.Get("/shares/alias/{alias}/download", h.ServeDownload)
	r.Head("/shares/alias/{alias}/download", h.ServeDownload)
}

// maxConcurrentDownloadsPerShare is the cap enforced by dlGate. Picked
// to be high enough that legitimate prefetchers / mobile retries don't
// trip it, low enough that one share can't sustain hundreds of
// parallel S3 fetches.
const maxConcurrentDownloadsPerShare = 8

// maxFolderRecursionDepth caps how deep streamFolderIntoZip recurses.
// Real shares rarely nest past ~5 levels; the bound is purely defensive
// against malicious parent-chain construction that would blow the
// Go stack.
const maxFolderRecursionDepth = 64

// ServeDownload handles GET /shares/alias/{alias}/download. See the
// section header above for the contract.
func (h *Handler) ServeDownload(w http.ResponseWriter, r *http.Request) {
	if h.S3 == nil {
		// L-DL1: don't leak err.Error() to anonymous callers.
		http.Error(w, "S3 not configured", http.StatusInternalServerError)
		return
	}
	alias := chi.URLParam(r, "alias")

	// Resolve alias → shareID + name + security row in one trip.
	var shareID string
	var shareName *string
	var hashedPwd *string
	var maxViews *int
	var views int
	var exp *time.Time
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT s.id, s.name, sec.password, sec.maxViews, s.views, s.expiration
		FROM shares s
		JOIN share_aliases sa ON sa.shareId = s.id
		JOIN share_security sec ON sec.id = s.securityId
		WHERE sa.alias = ?`, alias).
		Scan(&shareID, &shareName, &hashedPwd, &maxViews, &views, &exp)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	pwd := passwordFromAuthHeader(r)
	if pwd == "" {
		pwd = r.Header.Get("X-Share-Password")
	}

	if hashedPwd != nil && *hashedPwd != "" {
		// Reuse the M1 throttle so brute-forcing through this endpoint
		// counts against the same bucket as the SPA path.
		maxAttempts, blockSeconds := h.pwThrottleConfig(r.Context())
		throttle := h.pwThrottleHandle()
		if blocked := throttle.blockedFor(shareID, maxAttempts, time.Duration(blockSeconds)*time.Second); blocked > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(blocked.Round(time.Second).Seconds())))
			http.Error(w,
				"too many failed password attempts; try again in "+blocked.Round(time.Second).String(),
				http.StatusTooManyRequests)
			return
		}
		if pwd == "" {
			challengeBasicAuth(w, shareName)
			return
		}
		if !auth.VerifyPassword(pwd, *hashedPwd) {
			throttle.recordFailure(shareID)
			challengeBasicAuth(w, shareName)
			return
		}
		throttle.reset(shareID)
	}

	// M-DL1: per-share concurrent download cap. Acquired after the
	// password check so an attacker without the right password can't
	// burn slots; released by the defer below in all code paths.
	gate := h.dlGateHandle()
	if !gate.acquire(shareID) {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many concurrent downloads of this share; try again shortly", http.StatusTooManyRequests)
		return
	}
	defer gate.release(shareID)

	// Expiry gate.
	if exp != nil && exp.Before(time.Now()) {
		http.Error(w, "share has expired", http.StatusGone)
		return
	}

	// L-DL4/L-DL5: atomic check-and-increment for views, replacing the
	// pre-fix sequence of `if views >= maxViews → 410; UPDATE views =
	// views + 1`. The earlier shape let two concurrent callers both
	// pass the >= check before either incremented, so a maxViews=N
	// share could be downloaded N+k times under parallel load. The
	// CAS WHERE clause shipped here only matches when there's room
	// left (or no cap is set), and we treat zero rows affected as
	// "max reached".
	var maxArg interface{}
	if maxViews != nil {
		maxArg = *maxViews
	}
	res, dbErr := h.DB.ExecContext(r.Context(), `
		UPDATE shares
		SET views = views + 1
		WHERE id = ?
		  AND (? IS NULL OR views < ?)`,
		shareID, maxArg, maxArg)
	if dbErr != nil {
		slog.Error("share download: bump views", "share", shareID, "err", dbErr)
		http.Error(w, errInternalMsg, http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		http.Error(w, "share has reached its max views", http.StatusGone)
		return
	}

	files, folders, err := h.loadShareContent(r.Context(), shareID)
	if err != nil {
		slog.Error("share download: load content", "share", shareID, "err", err)
		http.Error(w, errInternalMsg, http.StatusInternalServerError)
		return
	}
	if len(files) == 0 && len(folders) == 0 {
		http.Error(w, "share is empty", http.StatusGone)
		return
	}

	// Common headers for both single-file (302) and zip paths.
	// M-DL2: Cache-Control private+no-store so a shared HTTP cache
	// can't store a password-gated share's bytes. Belt-and-suspenders
	// alongside the share password itself.
	w.Header().Set("Cache-Control", "private, no-store")

	// Single-file shortcut: redirect to a presigned URL so RustFS
	// streams the bytes directly and we don't pay backend bandwidth.
	if len(files) == 1 && len(folders) == 0 {
		f := files[0]
		presignedURL, err := h.S3.PresignGet(r.Context(), f.ObjectName, safeZipName(f.Name+"."+f.Extension))
		if err != nil {
			slog.Error("share download: presign", "share", shareID, "err", err)
			http.Error(w, errInternalMsg, http.StatusInternalServerError)
			return
		}
		// http.Redirect already skips the body for HEAD requests
		// (Go's stdlib checks r.Method internally), so we don't
		// need an explicit guard here.
		http.Redirect(w, r, presignedURL, http.StatusFound)
		return
	}

	// Multi-file or has folders → stream a zip.
	zipName := alias
	if shareName != nil && *shareName != "" {
		zipName = *shareName
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDispositionAttachment(zipName+".zip"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Zip output is generated on the fly — clients can't seek to a
	// byte offset without replaying the whole stream, and the bytes
	// aren't reproducible (timestamps in the zip headers differ run
	// to run). Explicitly disable range requests so curl -C - bails
	// out fast instead of producing corrupt resumes.
	w.Header().Set("Accept-Ranges", "none")

	// L-DL2: HEAD probes — answer with headers only, no body. Skip
	// the zip stream entirely.
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Top-level files: kept at the zip root. safeZipName neutralises
	// path separators / leading dots so a file named `../../foo` can't
	// land outside the extraction target (H-DL1, M-DL3).
	for _, f := range files {
		entry := safeZipName(f.Name + "." + f.Extension)
		if err := h.streamObjectIntoZip(r.Context(), zw, f.ObjectName, entry); err != nil {
			// We've already written headers + partial zip bytes —
			// can't switch to a JSON error. Best we can do is stop
			// writing; the client sees a truncated archive and the
			// `defer zw.Close()` will still flush central directory.
			slog.Warn("share download: stream object", "share", shareID, "object", f.ObjectName, "err", err)
			return
		}
	}
	// Folders: walk recursively. Each folder becomes a directory
	// prefix in the zip; files inside get nested paths. Each
	// component is sanitised, and the recursion is bounded by
	// maxFolderRecursionDepth to keep a malicious nesting from
	// blowing the goroutine stack.
	for _, fol := range folders {
		prefix := safeZipName(fol.Name)
		if err := h.streamFolderIntoZip(r.Context(), zw, fol.ID, prefix, 0); err != nil {
			slog.Warn("share download: stream folder", "share", shareID, "folder", fol.ID, "err", err)
			return
		}
	}
}

// loadShareContent returns the (top-level files, top-level folders)
// of a share. Folder content is walked separately at zip time so we
// can keep the file-row loader simple.
func (h *Handler) loadShareContent(ctx context.Context, shareID string) ([]FileSummary, []FolderSummary, error) {
	var files []FileSummary
	rowsF, err := h.DB.QueryxContext(ctx, `
		SELECT f.id, f.name, f.description, f.extension, f.size, f.objectName, f.userId, f.folderId, f.createdAt, f.updatedAt
		FROM files f JOIN _ShareFiles sf ON sf.A = f.id WHERE sf.B = ?`, shareID)
	if err != nil {
		return nil, nil, err
	}
	defer rowsF.Close()
	for rowsF.Next() {
		var fs FileSummary
		var created, updated dbtypes.PrismaTime
		if err := rowsF.Scan(&fs.ID, &fs.Name, &fs.Description, &fs.Extension, &fs.Size, &fs.ObjectName, &fs.UserID, &fs.FolderID, &created, &updated); err == nil {
			files = append(files, fs)
		}
	}

	var folders []FolderSummary
	rowsG, err := h.DB.QueryxContext(ctx, `
		SELECT f.id, f.name, f.description, f.parentId, f.createdAt, f.updatedAt
		FROM folders f JOIN _ShareFolders sf ON sf.A = f.id WHERE sf.B = ?`, shareID)
	if err != nil {
		return nil, nil, err
	}
	defer rowsG.Close()
	for rowsG.Next() {
		var fs FolderSummary
		var created, updated dbtypes.PrismaTime
		if err := rowsG.Scan(&fs.ID, &fs.Name, &fs.Description, &fs.ParentID, &created, &updated); err == nil {
			folders = append(folders, fs)
		}
	}
	return files, folders, nil
}

// streamObjectIntoZip pulls one S3 object and writes it to the zip
// stream at `entryName`. On error it returns without writing — the
// zip is left in a partial state for the caller to handle.
func (h *Handler) streamObjectIntoZip(ctx context.Context, zw *zip.Writer, objectName, entryName string) error {
	out, err := h.S3.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	w, err := zw.Create(entryName)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, out.Body)
	return err
}

// streamFolderIntoZip walks one share-attached folder depth-first and
// writes its files into the zip at `prefix/...`. parentId-based
// recursion keeps each level cheap (one indexed query per folder
// instead of a recursive CTE).
//
// depth is bounded by maxFolderRecursionDepth (L-DL3) — past that we
// stop recursing silently. Each name component is run through
// safeZipName before being joined into the path so a folder named
// `../escape` can't bubble out of the zip root (H-DL1).
func (h *Handler) streamFolderIntoZip(ctx context.Context, zw *zip.Writer, folderID, prefix string, depth int) error {
	if depth > maxFolderRecursionDepth {
		// Truncate silently — the alternative (returning an error)
		// would abort the whole download. Real-world shares never
		// nest this deep, so a trip here means malicious nesting.
		return nil
	}
	// Files directly inside this folder.
	rowsF, err := h.DB.QueryxContext(ctx,
		`SELECT name, extension, objectName FROM files WHERE folderId = ?`, folderID)
	if err != nil {
		return err
	}
	type f struct{ name, ext, obj string }
	var files []f
	for rowsF.Next() {
		var x f
		if err := rowsF.Scan(&x.name, &x.ext, &x.obj); err == nil {
			files = append(files, x)
		}
	}
	rowsF.Close()
	for _, x := range files {
		entry := path.Join(prefix, safeZipName(x.name+"."+x.ext))
		if err := h.streamObjectIntoZip(ctx, zw, x.obj, entry); err != nil {
			return err
		}
	}
	// Recurse into child folders.
	rowsG, err := h.DB.QueryxContext(ctx,
		`SELECT id, name FROM folders WHERE parentId = ?`, folderID)
	if err != nil {
		return err
	}
	type fol struct{ id, name string }
	var subs []fol
	for rowsG.Next() {
		var x fol
		if err := rowsG.Scan(&x.id, &x.name); err == nil {
			subs = append(subs, x)
		}
	}
	rowsG.Close()
	for _, s := range subs {
		sub := path.Join(prefix, safeZipName(s.name))
		if err := h.streamFolderIntoZip(ctx, zw, s.id, sub, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// passwordFromAuthHeader extracts the password portion of a Basic auth
// header. We deliberately ignore the username — share passwords don't
// have a user identifier on the request side, and forcing curl users
// to type `-u user:secret` instead of `-u :secret` would surprise.
func passwordFromAuthHeader(r *http.Request) string {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Basic ") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Basic "))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// challengeBasicAuth writes the 401 + WWW-Authenticate header so curl
// (`curl -u : URL`) prompts interactively and shell scripts can detect
// auth requirement programmatically.
func challengeBasicAuth(w http.ResponseWriter, shareName *string) {
	realm := "Palmr share"
	if shareName != nil && *shareName != "" {
		// Strip quote/control chars from the realm string — they'd
		// break the WWW-Authenticate header otherwise.
		realm = `Palmr share — ` + sanitizeRealm(*shareName)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, "Password required", http.StatusUnauthorized)
}

// sanitizeRealm strips anything that would break the WWW-Authenticate
// header's quoted-string syntax — quote, backslash, control chars.
func sanitizeRealm(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// contentDispositionAttachment builds an RFC 5987-compliant
// Content-Disposition header value (L-DL6). Plain `filename="..."` is
// kept for legacy clients (it carries the ASCII-safe form), while a
// `filename*=UTF-8''...` parameter carries the original unicode for
// modern browsers / curl / wget. Without the starred form, names with
// non-ASCII characters get mangled by some clients.
func contentDispositionAttachment(filename string) string {
	ascii := asciiFallback(filename)
	header := `attachment; filename="` + ascii + `"`
	if !isASCII(filename) {
		header += `; filename*=UTF-8''` + url.PathEscape(filename)
	}
	return header
}

// asciiFallback produces the legacy `filename="..."` token. Quotes,
// backslashes and control characters would break the quoted-string
// syntax (or smuggle headers), so we replace them with underscores.
// Non-ASCII runes get the same treatment — they're allowed by some
// clients but rejected by others; the filename* parameter carries the
// real unicode anyway.
func asciiFallback(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" {
		return "download"
	}
	return out
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 0x7e || r < 0x20 {
			return false
		}
	}
	return true
}

// safeZipName converts a single user-supplied name into a single zip
// path component (H-DL1, M-DL3). The result never contains a path
// separator and never resolves above its parent directory, so naive
// `unzip` implementations can't be tricked into writing outside the
// extraction target.
//
// We replace `/`, `\`, and NUL with `_` (so a name like `foo/bar`
// becomes `foo_bar`, not a subdirectory); trim leading dots (so
// `..` / `.` / `.hidden` don't survive as their own segment); and
// substitute `_` when everything got stripped.
func safeZipName(raw string) string {
	if raw == "" {
		return "_"
	}
	cleaned := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 {
			return '_'
		}
		// Strip ASCII control bytes too — they're legal in unicode but
		// confuse a lot of tooling.
		if r < 0x20 {
			return '_'
		}
		return r
	}, raw)
	cleaned = strings.TrimLeft(cleaned, ".")
	if cleaned == "" {
		return "_"
	}
	return cleaned
}

// -----------------------------------------------------------------------------
// download gate — bounds the number of in-flight downloads per share
// (M-DL1). Process-local, deliberately small; the real "stop a
// botnet" answer is at the reverse proxy. This is just a backstop so
// one popular share can't drain the whole goroutine pool.
// -----------------------------------------------------------------------------

type downloadGate struct {
	mu       sync.Mutex
	inFlight map[string]int
	max      int
}

func newDownloadGate(max int) *downloadGate {
	if max <= 0 {
		max = 1
	}
	return &downloadGate{inFlight: map[string]int{}, max: max}
}

// acquire reserves a slot for shareID and returns true if granted.
// Callers MUST call release exactly once when granted, regardless of
// the response code they ended up writing.
func (g *downloadGate) acquire(shareID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight[shareID] >= g.max {
		return false
	}
	g.inFlight[shareID]++
	return true
}

func (g *downloadGate) release(shareID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inFlight[shareID]--
	if g.inFlight[shareID] <= 0 {
		delete(g.inFlight, shareID)
	}
}

// dlGateHandle returns the live gate, allocating one on first use if
// the Handler was constructed via bare-literal (the constructor path
// initialises it eagerly, but the legacy pattern still works).
func (h *Handler) dlGateHandle() *downloadGate {
	if h.dlGate == nil {
		h.dlGate = newDownloadGate(maxConcurrentDownloadsPerShare)
	}
	return h.dlGate
}
