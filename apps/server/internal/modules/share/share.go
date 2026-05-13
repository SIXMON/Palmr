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
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

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
	UserID      string            `json:"userId"`
	FolderID    *string           `json:"folderId"`
	CreatedAt   string            `json:"createdAt"`
	UpdatedAt   string            `json:"updatedAt"`
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

	// Attach files (M2M table: _ShareFiles)
	for _, fid := range in.Body.Files {
		if fid == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO _ShareFiles (A, B) VALUES (?, ?)`, fid, id); err != nil {
			return nil, apperr.Internal("attach file: " + err.Error())
		}
	}
	for _, fid := range in.Body.Folders {
		if fid == "" {
			continue
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
	for _, fid := range in.Body.Files {
		dbtypes.LogBestEffort(ctx, "share.share.insert.or.ignore.into", h.DB, `INSERT OR IGNORE INTO _ShareFiles (A, B) VALUES (?, ?)`, fid, in.ShareID)
	}
	for _, fid := range in.Body.Folders {
		dbtypes.LogBestEffort(ctx, "share.share.insert.or.ignore.into", h.DB, `INSERT OR IGNORE INTO _ShareFolders (A, B) VALUES (?, ?)`, fid, in.ShareID)
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
type ShareAliasBody struct {
	Alias   string `json:"alias"`
	ShareID string `json:"shareId"`
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
	out := &ShareAliasOutput{}
	out.Body.Alias.Alias = alias
	out.Body.Alias.ShareID = in.ShareID
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
		if pwd == "" {
			return nil, apperr.Unauthorized("Password required")
		}
		if !auth.VerifyPassword(pwd, *sec.Password) {
			return nil, apperr.Unauthorized("Invalid password")
		}
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

// fullViewMany is the batched cousin of fullView. It runs five SELECTs
// (one per relation table) regardless of how many shares are requested
// and assembles the result in Go, killing the N+1 round-trip pattern
// the single-id version creates when /shares/me has dozens of rows.
//
// `withRecipients` toggles the recipients fan-out — true for the owner
// view, false for public alias views (which already exclude recipients).
func (h *Handler) fullViewMany(ctx context.Context, ids []string, withRecipients bool) ([]publicView, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	// 1) Shares + security in one go (JOIN on share_security.id).
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

	// 2) Files via M2M, in one query.
	if q, args, err := sqlx.In(`
		SELECT sf.B, f.id, f.name, f.description, f.extension, f.size, f.objectName, f.userId, f.folderId, f.createdAt, f.updatedAt
		FROM _ShareFiles sf JOIN files f ON sf.A = f.id WHERE sf.B IN (?)`, ids); err == nil {
		rf, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
		if rf != nil {
			for rf.Next() {
				var shareID string
				var fs FileSummary
				var created, updated dbtypes.PrismaTime
				if err := rf.Scan(&shareID, &fs.ID, &fs.Name, &fs.Description, &fs.Extension, &fs.Size,
					&fs.ObjectName, &fs.UserID, &fs.FolderID, &created, &updated); err != nil {
					continue
				}
				fs.CreatedAt = created.Time.Format(time.RFC3339)
				fs.UpdatedAt = updated.Time.Format(time.RFC3339)
				if v, ok := views[shareID]; ok {
					v.Files = append(v.Files, fs)
				}
			}
			rf.Close()
		}
	}

	// 3) Folders via M2M, in one query.
	if q, args, err := sqlx.In(`
		SELECT sf.B, f.id, f.name, f.description, f.parentId, f.createdAt, f.updatedAt
		FROM _ShareFolders sf JOIN folders f ON sf.A = f.id WHERE sf.B IN (?)`, ids); err == nil {
		rg, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
		if rg != nil {
			for rg.Next() {
				var shareID string
				var fs FolderSummary
				var created, updated dbtypes.PrismaTime
				if err := rg.Scan(&shareID, &fs.ID, &fs.Name, &fs.Description, &fs.ParentID, &created, &updated); err != nil {
					continue
				}
				fs.CreatedAt = created.Time.Format(time.RFC3339)
				fs.UpdatedAt = updated.Time.Format(time.RFC3339)
				if v, ok := views[shareID]; ok {
					v.Folders = append(v.Folders, fs)
				}
			}
			rg.Close()
		}
	}

	// 4) Aliases.
	if q, args, err := sqlx.In(`
		SELECT id, alias, shareId, createdAt, updatedAt FROM share_aliases WHERE shareId IN (?)`, ids); err == nil {
		ra, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
		if ra != nil {
			for ra.Next() {
				var av aliasView
				var created, updated dbtypes.PrismaTime
				if err := ra.Scan(&av.ID, &av.Alias, &av.ShareID, &created, &updated); err != nil {
					continue
				}
				av.CreatedAt = created.Time.Format(time.RFC3339)
				av.UpdatedAt = updated.Time.Format(time.RFC3339)
				if v, ok := views[av.ShareID]; ok {
					v.Alias = &av
				}
			}
			ra.Close()
		}
	}

	// 5) Recipients (only when the caller wants the owner view).
	if withRecipients {
		if q, args, err := sqlx.In(`
			SELECT shareId, id, email, createdAt, updatedAt FROM share_recipients WHERE shareId IN (?)`, ids); err == nil {
			rr, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
			if rr != nil {
				for rr.Next() {
					var shareID string
					var r recipientView
					var created, updated dbtypes.PrismaTime
					if err := rr.Scan(&shareID, &r.ID, &r.Email, &created, &updated); err != nil {
						continue
					}
					r.CreatedAt = created.Time.Format(time.RFC3339)
					r.UpdatedAt = updated.Time.Format(time.RFC3339)
					if v, ok := views[shareID]; ok {
						v.Recipients = append(v.Recipients, r)
					}
				}
				rr.Close()
			}
		}
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
