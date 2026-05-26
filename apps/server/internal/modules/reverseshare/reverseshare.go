// Package reverseshare implements the anonymous-upload feature.
//
// Owner endpoints (auth):
//   POST   /reverse-shares                            create
//   GET    /reverse-shares                            list mine
//   GET    /reverse-shares/{id}                       details
//   PUT    /reverse-shares                            update
//   DELETE /reverse-shares/{id}                       delete
//   PATCH  /reverse-shares/{id}/activate              activate
//   PATCH  /reverse-shares/{id}/deactivate            deactivate
//   PUT    /reverse-shares/{id}/password              set/clear password
//   POST   /reverse-shares/{reverseShareId}/alias     create alias
//
// Anonymous (public) endpoints, by alias:
//   GET    /reverse-shares/alias/{alias}/upload       page metadata
//   POST   /reverse-shares/alias/{alias}/presigned-url   PUT URL
//   POST   /reverse-shares/alias/{alias}/register-file   register completed upload
//   POST   /reverse-shares/alias/{alias}/multipart/create
//   GET    /reverse-shares/alias/{alias}/multipart/part-url
//   POST   /reverse-shares/alias/{alias}/multipart/complete
//   POST   /reverse-shares/alias/{alias}/multipart/abort
//   POST   /reverse-shares/{id}/check-password        password gate
//   GET    /reverse-shares/alias/{alias}/metadata     OpenGraph
//
// Owner-side file management:
//   GET    /reverse-shares/files/{fileId}/download    presigned download
//   DELETE /reverse-shares/files/{fileId}             delete uploaded file
//   PUT    /reverse-shares/files/{fileId}             update name/description
//   POST   /reverse-shares/files/{fileId}/copy        copy into the owner's own files
package reverseshare

import (
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
	"github.com/sixmon/palmr/apps/server/internal/storage"
)

// Shared error / path literals. Extracted so the strings don't drift
// out of sync across handlers and so the sonar-flagged S1192 dupes
// collapse to a single source of truth.
const (
	errReverseShareNotFound  = "reverse share not found"
	errNotYourReverseShare   = "not your reverse-share"
	errObjectNotInShare      = "objectName does not belong to this reverse share"
	errS3NotConfigured       = "S3 not configured"
	errFileNotFound          = "file not found"
	objectPrefixReverseShare = "reverse-shares/"
	routeReverseShares       = "/reverse-shares"
)

// ReverseShare mirrors the reverse_shares row 1:1.
type ReverseShare struct {
	ID                 string              `db:"id"                 json:"id"`
	Name               *string             `db:"name"               json:"name"`
	Description        *string             `db:"description"        json:"description"`
	Expiration         *dbtypes.PrismaTime `db:"expiration"         json:"expiration"`
	MaxFiles           *int                `db:"maxFiles"           json:"maxFiles"`
	MaxFileSize        *int64              `db:"maxFileSize"        json:"maxFileSize"`
	AllowedFileTypes   *string             `db:"allowedFileTypes"   json:"allowedFileTypes"`
	Password           *string             `db:"password"           json:"-"`
	PageLayout         string              `db:"pageLayout"         json:"pageLayout"`
	IsActive           bool                `db:"isActive"           json:"isActive"`
	NameFieldRequired  string              `db:"nameFieldRequired"  json:"nameFieldRequired"`
	EmailFieldRequired string              `db:"emailFieldRequired" json:"emailFieldRequired"`
	CreatorID          string              `db:"creatorId"          json:"creatorId"`
	CreatedAt          dbtypes.PrismaTime  `db:"createdAt"          json:"createdAt"`
	UpdatedAt          dbtypes.PrismaTime  `db:"updatedAt"          json:"updatedAt"`
}

// ReverseShareFile mirrors reverse_share_files row 1:1.
type ReverseShareFile struct {
	ID            string             `db:"id"            json:"id"`
	Name          string             `db:"name"          json:"name"`
	Description   *string            `db:"description"   json:"description"`
	Extension     string             `db:"extension"     json:"extension"`
	Size          dbtypes.BigIntStr  `db:"size"          json:"size"`
	ObjectName    string             `db:"objectName"    json:"objectName"`
	UploaderEmail *string            `db:"uploaderEmail" json:"uploaderEmail"`
	UploaderName  *string            `db:"uploaderName"  json:"uploaderName"`
	CreatedAt     dbtypes.PrismaTime `db:"createdAt"     json:"createdAt"`
	UpdatedAt     dbtypes.PrismaTime `db:"updatedAt"     json:"updatedAt"`
}

// ReverseShareAlias mirrors reverse_share_aliases row 1:1.
type ReverseShareAlias struct {
	ID             string             `db:"id"             json:"id"`
	Alias          string             `db:"alias"          json:"alias"`
	ReverseShareID string             `db:"reverseShareId" json:"reverseShareId"`
	CreatedAt      dbtypes.PrismaTime `db:"createdAt"      json:"createdAt"`
	UpdatedAt      dbtypes.PrismaTime `db:"updatedAt"      json:"updatedAt"`
}

// ReverseShareWithRel is what the admin UI consumes: the row plus its
// alias and uploaded files, plus a synthesized hasPassword flag.
type ReverseShareWithRel struct {
	ReverseShare
	HasPassword bool               `json:"hasPassword"`
	Files       []ReverseShareFile `json:"files"`
	Alias       *ReverseShareAlias `json:"alias"`
}

type Handler struct {
	DB *sqlx.DB
	S3 *storage.S3
}

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"Reverse Share"}, OperationID: id}
	}

	// Owner
	huma.Register(api, op(http.MethodPost, routeReverseShares, "createReverseShare"), h.Create)
	huma.Register(api, op(http.MethodGet, routeReverseShares, "listReverseShares"), h.List)
	huma.Register(api, op(http.MethodGet, "/reverse-shares/{id}", "getReverseShare"), h.Get)
	huma.Register(api, op(http.MethodPut, routeReverseShares, "updateReverseShare"), h.Update)
	huma.Register(api, op(http.MethodDelete, "/reverse-shares/{id}", "deleteReverseShare"), h.Delete)
	huma.Register(api, op(http.MethodPatch, "/reverse-shares/{id}/activate", "activateReverseShare"), h.Activate)
	huma.Register(api, op(http.MethodPatch, "/reverse-shares/{id}/deactivate", "deactivateReverseShare"), h.Deactivate)
	huma.Register(api, op(http.MethodPut, "/reverse-shares/{id}/password", "setReverseSharePassword"), h.SetPassword)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/{reverseShareId}/alias", "createReverseShareAlias"), h.CreateAlias)

	// Owner-side file management
	huma.Register(api, op(http.MethodGet, "/reverse-shares/files/{fileId}/download", "downloadReverseShareFile"), h.DownloadFile)
	huma.Register(api, op(http.MethodDelete, "/reverse-shares/files/{fileId}", "deleteReverseShareFile"), h.DeleteFile)
	huma.Register(api, op(http.MethodPut, "/reverse-shares/files/{fileId}", "updateReverseShareFile"), h.UpdateFile)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/files/{fileId}/copy", "copyReverseShareFile"), h.CopyFile)

	// Public (anonymous) endpoints by alias
	huma.Register(api, op(http.MethodGet, "/reverse-shares/alias/{alias}/upload", "getReverseShareUpload"), h.PublicGet)
	huma.Register(api, op(http.MethodGet, "/reverse-shares/{id}/upload", "getReverseShareUploadById"), h.PublicGetByID)
	huma.Register(api, op(http.MethodGet, "/reverse-shares/alias/{alias}/metadata", "getReverseShareMetadata"), h.AliasMetadata)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/alias/{alias}/presigned-url", "getPresignedUrlByAlias"), h.PresignByAlias)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/{id}/presigned-url", "getPresignedUrlByID"), h.PresignByID)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/alias/{alias}/register-file", "registerFileByAlias"), h.RegisterFileByAlias)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/{id}/register-file", "registerFileByID"), h.RegisterFileByID)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/{id}/check-password", "checkReverseSharePassword"), h.CheckPassword)

	huma.Register(api, op(http.MethodPost, "/reverse-shares/alias/{alias}/multipart/create", "createMultipartByAlias"), h.MultipartCreate)
	huma.Register(api, op(http.MethodGet, "/reverse-shares/alias/{alias}/multipart/part-url", "getMultipartPartUrlByAlias"), h.MultipartPart)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/alias/{alias}/multipart/complete", "completeMultipartByAlias"), h.MultipartComplete)
	huma.Register(api, op(http.MethodPost, "/reverse-shares/alias/{alias}/multipart/abort", "abortMultipartByAlias"), h.MultipartAbort)
}

// -----------------------------------------------------------------------------
// Owner: create / list / get / update / delete / activate / deactivate
// -----------------------------------------------------------------------------

type RSCreateInput struct {
	Body struct {
		Name             *string `json:"name,omitempty"`
		Description      *string `json:"description,omitempty"`
		Expiration       *string `json:"expiration,omitempty" format:"date-time"`
		MaxFiles         *int    `json:"maxFiles,omitempty"`
		MaxFileSize      *int64  `json:"maxFileSize,omitempty"`
		AllowedFileTypes *string `json:"allowedFileTypes,omitempty"`
		Password         *string `json:"password,omitempty"`
		// UI form fields. Persisted as-is on the reverse_shares row.
		PageLayout         *string `json:"pageLayout,omitempty"`
		NameFieldRequired  *string `json:"nameFieldRequired,omitempty"`
		EmailFieldRequired *string `json:"emailFieldRequired,omitempty"`
	}
}

type RSSingleOutput struct {
	Body struct {
		ReverseShare ReverseShareWithRel `json:"reverseShare"`
	}
}
type RSListOutput struct {
	Body struct {
		ReverseShares []ReverseShareWithRel `json:"reverseShares"`
	}
}
type RSMsgOutput struct{ Body struct{ Message string `json:"message"` } }

func (h *Handler) Create(ctx context.Context, in *RSCreateInput) (*RSSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	var hashedPwd *string
	if in.Body.Password != nil && *in.Body.Password != "" {
		hp, err := auth.HashPassword(*in.Body.Password, 12)
		if err != nil {
			return nil, apperr.BadRequest(err.Error())
		}
		hashedPwd = &hp
	}
	var exp *time.Time
	if in.Body.Expiration != nil {
		if t, err := time.Parse(time.RFC3339, *in.Body.Expiration); err == nil {
			exp = &t
		}
	}
	pageLayout := stringOr(in.Body.PageLayout, "DEFAULT")
	nameReq := stringOr(in.Body.NameFieldRequired, "OPTIONAL")
	emailReq := stringOr(in.Body.EmailFieldRequired, "OPTIONAL")
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO reverse_shares (id, name, description, expiration, maxFiles, maxFileSize, allowedFileTypes, password, pageLayout, isActive, nameFieldRequired, emailFieldRequired, createdAt, updatedAt, creatorId)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
		id, in.Body.Name, in.Body.Description, exp, in.Body.MaxFiles, in.Body.MaxFileSize, in.Body.AllowedFileTypes,
		hashedPwd, pageLayout, nameReq, emailReq, now, now, uc.UserID)
	if err != nil {
		return nil, apperr.Internal("create reverse-share: " + err.Error())
	}
	rs, _ := h.loadWithRel(ctx, id)
	out := &RSSingleOutput{}
	out.Body.ReverseShare = rs
	return out, nil
}

func (h *Handler) List(ctx context.Context, _ *struct{}) (*RSListOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &RSListOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.ReverseShares = []ReverseShareWithRel{}
	// Single SELECT for the rows, then batch-load files + aliases in
	// O(1) queries → 3 round-trips total whatever the user owns.
	var rows []ReverseShare
	if err := h.DB.SelectContext(ctx, &rows, `
		SELECT id, name, description, expiration, maxFiles, maxFileSize, allowedFileTypes, password,
		       pageLayout, isActive, nameFieldRequired, emailFieldRequired, creatorId, createdAt, updatedAt
		FROM reverse_shares WHERE creatorId = ? ORDER BY createdAt DESC`, uc.UserID); err != nil {
		return out, nil
	}
	if len(rows) == 0 {
		return out, nil
	}
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}

	// Batch-load files keyed by reverseShareId.
	filesByRS := map[string][]ReverseShareFile{}
	if q, args, err := sqlx.In(`
		SELECT id, name, description, extension, size, objectName, uploaderEmail, uploaderName, reverseShareId, createdAt, updatedAt
		FROM reverse_share_files WHERE reverseShareId IN (?) ORDER BY createdAt ASC`, ids); err == nil {
		rf, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
		if rf != nil {
			for rf.Next() {
				var f ReverseShareFile
				var rsID string
				if err := rf.Scan(&f.ID, &f.Name, &f.Description, &f.Extension, &f.Size, &f.ObjectName,
					&f.UploaderEmail, &f.UploaderName, &rsID, &f.CreatedAt, &f.UpdatedAt); err == nil {
					filesByRS[rsID] = append(filesByRS[rsID], f)
				}
			}
			rf.Close()
		}
	}

	// Batch-load aliases.
	aliasByRS := map[string]*ReverseShareAlias{}
	if q, args, err := sqlx.In(`
		SELECT id, alias, reverseShareId, createdAt, updatedAt FROM reverse_share_aliases WHERE reverseShareId IN (?)`, ids); err == nil {
		ra, _ := h.DB.QueryxContext(ctx, h.DB.Rebind(q), args...)
		if ra != nil {
			for ra.Next() {
				var a ReverseShareAlias
				if err := ra.Scan(&a.ID, &a.Alias, &a.ReverseShareID, &a.CreatedAt, &a.UpdatedAt); err == nil {
					aRef := a
					aliasByRS[a.ReverseShareID] = &aRef
				}
			}
			ra.Close()
		}
	}

	out.Body.ReverseShares = make([]ReverseShareWithRel, 0, len(rows))
	for _, r := range rows {
		// Ensure a missing entry in the files map still serialises as
		// `[]`, not `null` — the React UI calls `.length` / `.map` on it.
		files := filesByRS[r.ID]
		if files == nil {
			files = []ReverseShareFile{}
		}
		out.Body.ReverseShares = append(out.Body.ReverseShares, ReverseShareWithRel{
			ReverseShare: r,
			HasPassword:  r.Password != nil && *r.Password != "",
			Files:        files,
			Alias:        aliasByRS[r.ID],
		})
	}
	return out, nil
}

type RSGetInput struct{ ID string `path:"id"` }

func (h *Handler) Get(ctx context.Context, in *RSGetInput) (*RSSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	rs, err := h.loadWithRel(ctx, in.ID)
	if err != nil || rs.CreatorID != uc.UserID {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	out := &RSSingleOutput{}
	out.Body.ReverseShare = rs
	return out, nil
}

type RSUpdateInput struct {
	Body struct {
		ID                 string  `json:"id" required:"true"`
		Name               *string `json:"name,omitempty"`
		Description        *string `json:"description,omitempty"`
		Expiration         *string `json:"expiration,omitempty" format:"date-time"`
		MaxFiles           *int    `json:"maxFiles,omitempty"`
		MaxFileSize        *int64  `json:"maxFileSize,omitempty"`
		AllowedFileTypes   *string `json:"allowedFileTypes,omitempty"`
		Password           *string `json:"password,omitempty"`
		IsActive           *bool   `json:"isActive,omitempty"`
		PageLayout         *string `json:"pageLayout,omitempty"`
		NameFieldRequired  *string `json:"nameFieldRequired,omitempty"`
		EmailFieldRequired *string `json:"emailFieldRequired,omitempty"`
	}
}

func (h *Handler) Update(ctx context.Context, in *RSUpdateInput) (*RSSingleOutput, error) {
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
	if in.Body.MaxFiles != nil {
		fields = append(fields, "maxFiles = ?")
		args = append(args, *in.Body.MaxFiles)
	}
	if in.Body.MaxFileSize != nil {
		fields = append(fields, "maxFileSize = ?")
		args = append(args, *in.Body.MaxFileSize)
	}
	if in.Body.AllowedFileTypes != nil {
		fields = append(fields, "allowedFileTypes = ?")
		args = append(args, *in.Body.AllowedFileTypes)
	}
	if in.Body.IsActive != nil {
		fields = append(fields, "isActive = ?")
		args = append(args, *in.Body.IsActive)
	}
	if in.Body.PageLayout != nil {
		fields = append(fields, "pageLayout = ?")
		args = append(args, *in.Body.PageLayout)
	}
	if in.Body.NameFieldRequired != nil {
		fields = append(fields, "nameFieldRequired = ?")
		args = append(args, *in.Body.NameFieldRequired)
	}
	if in.Body.EmailFieldRequired != nil {
		fields = append(fields, "emailFieldRequired = ?")
		args = append(args, *in.Body.EmailFieldRequired)
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
		fields = append(fields, "password = ?")
		args = append(args, hashed)
	}
	if in.Body.Expiration != nil {
		if t, err := time.Parse(time.RFC3339, *in.Body.Expiration); err == nil {
			fields = append(fields, "expiration = ?")
			args = append(args, t)
		}
	}
	if len(fields) == 0 {
		return nil, apperr.BadRequest("nothing to update")
	}
	fields = append(fields, "updatedAt = CURRENT_TIMESTAMP")
	args = append(args, in.Body.ID)
	q := "UPDATE reverse_shares SET " + strings.Join(fields, ", ") + " WHERE id = ?"
	if _, err := h.DB.ExecContext(ctx, q, args...); err != nil {
		return nil, apperr.Internal("update reverse-share")
	}
	rs, _ := h.loadWithRel(ctx, in.Body.ID)
	out := &RSSingleOutput{}
	out.Body.ReverseShare = rs
	return out, nil
}

func (h *Handler) Delete(ctx context.Context, in *RSGetInput) (*RSMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM reverse_shares WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete reverse-share")
	}
	out := &RSMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

func (h *Handler) Activate(ctx context.Context, in *RSGetInput) (*RSSingleOutput, error) {
	return h.setActive(ctx, in.ID, true)
}
func (h *Handler) Deactivate(ctx context.Context, in *RSGetInput) (*RSSingleOutput, error) {
	return h.setActive(ctx, in.ID, false)
}
func (h *Handler) setActive(ctx context.Context, id string, active bool) (*RSSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, id, uc.UserID); err != nil {
		return nil, err
	}
	dbtypes.LogBestEffort(ctx, "reverseshare.reverseshare.update.reverse_shares.set.isactive", h.DB, `UPDATE reverse_shares SET isActive = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, active, id)
	rs, _ := h.loadWithRel(ctx, id)
	out := &RSSingleOutput{}
	out.Body.ReverseShare = rs
	return out, nil
}

type RSPasswordInput struct {
	ID   string `path:"id"`
	Body struct {
		Password *string `json:"password"`
	}
}

func (h *Handler) SetPassword(ctx context.Context, in *RSPasswordInput) (*RSSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	var hashed *string
	if in.Body.Password != nil && *in.Body.Password != "" {
		hp, err := auth.HashPassword(*in.Body.Password, 12)
		if err != nil {
			return nil, apperr.BadRequest(err.Error())
		}
		hashed = &hp
	}
	_, err = h.DB.ExecContext(ctx, `UPDATE reverse_shares SET password = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, hashed, in.ID)
	if err != nil {
		return nil, apperr.Internal("set password")
	}
	rs, _ := h.loadWithRel(ctx, in.ID)
	out := &RSSingleOutput{}
	out.Body.ReverseShare = rs
	return out, nil
}

// -----------------------------------------------------------------------------
// Alias creation
// -----------------------------------------------------------------------------

type RSAliasInput struct {
	ReverseShareID string `path:"reverseShareId"`
	Body           struct {
		Alias *string `json:"alias,omitempty"`
	}
}
// RSAliasBody matches the frontend `ReverseShareAlias` type — 5 fields.
// Earlier this only carried {alias, reverseShareId}; the missing id /
// createdAt / updatedAt left consumers reading undefined.
type RSAliasBody struct {
	ID             string `json:"id"`
	Alias          string `json:"alias"`
	ReverseShareID string `json:"reverseShareId"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}
type RSAliasOutput struct {
	Body struct {
		Alias RSAliasBody `json:"alias"`
	}
}

func (h *Handler) CreateAlias(ctx context.Context, in *RSAliasInput) (*RSAliasOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ReverseShareID, uc.UserID); err != nil {
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
		`INSERT INTO reverse_share_aliases (id, alias, reverseShareId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)`,
		id, alias, in.ReverseShareID, now, now)
	if err != nil {
		return nil, apperr.Conflict("alias already exists")
	}
	stamp := now.Format(time.RFC3339)
	out := &RSAliasOutput{}
	out.Body.Alias = RSAliasBody{
		ID:             id,
		Alias:          alias,
		ReverseShareID: in.ReverseShareID,
		CreatedAt:      stamp,
		UpdatedAt:      stamp,
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Public anonymous endpoints
// -----------------------------------------------------------------------------

type RSPublicView struct {
	ID                 string     `json:"id"`
	Name               *string    `json:"name"`
	Description        *string    `json:"description"`
	Expiration         *time.Time `json:"expiration"`
	MaxFiles           *int       `json:"maxFiles"`
	MaxFileSize        *int64     `json:"maxFileSize"`
	AllowedFileTypes   *string    `json:"allowedFileTypes"`
	HasPassword        bool       `json:"hasPassword"`
	IsActive           bool       `json:"isActive"`
	CurrentFileCount   int        `json:"currentFileCount"`
	NameFieldRequired  string     `json:"nameFieldRequired"`
	EmailFieldRequired string     `json:"emailFieldRequired"`
	PageLayout         string     `json:"pageLayout"`
}

type RSPublicGetInput struct{ Alias string `path:"alias"` }
type RSPublicGetByIDInput struct{ ID string `path:"id"` }
type RSPublicGetOutput struct {
	Body struct {
		ReverseShare RSPublicView `json:"reverseShare"`
	}
}

func (h *Handler) PublicGet(ctx context.Context, in *RSPublicGetInput) (*RSPublicGetOutput, error) {
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	return h.publicGet(ctx, id)
}
func (h *Handler) PublicGetByID(ctx context.Context, in *RSPublicGetByIDInput) (*RSPublicGetOutput, error) {
	return h.publicGet(ctx, in.ID)
}

func (h *Handler) publicGet(ctx context.Context, id string) (*RSPublicGetOutput, error) {
	row := h.DB.QueryRowContext(ctx, `
		SELECT id, name, description, expiration, maxFiles, maxFileSize, allowedFileTypes,
		       password, isActive, pageLayout, nameFieldRequired, emailFieldRequired
		FROM reverse_shares WHERE id = ?`, id)
	var pv RSPublicView
	var pwd *string
	if err := row.Scan(&pv.ID, &pv.Name, &pv.Description, &pv.Expiration, &pv.MaxFiles, &pv.MaxFileSize,
		&pv.AllowedFileTypes, &pwd, &pv.IsActive, &pv.PageLayout, &pv.NameFieldRequired, &pv.EmailFieldRequired); err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	pv.HasPassword = pwd != nil && *pwd != ""
	_ = h.DB.GetContext(ctx, &pv.CurrentFileCount, `SELECT COUNT(*) FROM reverse_share_files WHERE reverseShareId = ?`, id)
	out := &RSPublicGetOutput{}
	out.Body.ReverseShare = pv
	return out, nil
}

type RSAliasMetaInput struct{ Alias string `path:"alias"` }

// RSAliasMetaOutput includes `maxFiles` so the reverse-share landing page
// (`apps/web/src/app/(shares)/r/[alias]/layout.tsx`) can switch its
// OpenGraph description to the "with limit" variant. Without it the layout
// always renders the generic copy.
type RSAliasMetaOutput struct {
	Body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		AppName     string  `json:"appName"`
		MaxFiles    *int    `json:"maxFiles"`
	}
}

func (h *Handler) AliasMetadata(ctx context.Context, in *RSAliasMetaInput) (*RSAliasMetaOutput, error) {
	out := &RSAliasMetaOutput{}
	_ = h.DB.QueryRowContext(ctx, `
		SELECT rs.name, rs.description, rs.maxFiles
		FROM reverse_shares rs JOIN reverse_share_aliases a ON a.reverseShareId = rs.id WHERE a.alias = ?`, in.Alias).
		Scan(&out.Body.Name, &out.Body.Description, &out.Body.MaxFiles)
	_ = h.DB.GetContext(ctx, &out.Body.AppName, `SELECT value FROM app_configs WHERE key = 'appName'`)
	if out.Body.AppName == "" {
		out.Body.AppName = "Palmr"
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Presigned URL flow
// -----------------------------------------------------------------------------

type PresignAliasInput struct {
	Alias    string `path:"alias"`
	Password string `query:"password"`
	Body     struct {
		Filename  string `json:"filename" required:"true"`
		Extension string `json:"extension" required:"true"`
		Size      *int64 `json:"size,omitempty"`
	}
}
type PresignIDInput struct {
	ID       string `path:"id"`
	Password string `query:"password"`
	Body     struct {
		Filename  string `json:"filename" required:"true"`
		Extension string `json:"extension" required:"true"`
		Size      *int64 `json:"size,omitempty"`
	}
}
type PresignOutput struct {
	Body struct {
		URL        string `json:"url"`
		ObjectName string `json:"objectName"`
		ExpiresIn  int    `json:"expiresIn"`
	}
}

func (h *Handler) PresignByAlias(ctx context.Context, in *PresignAliasInput) (*PresignOutput, error) {
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	rs, err := h.load(ctx, id)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	if err := h.validateUpload(ctx, rs, in.Password, in.Body.Extension, in.Body.Size); err != nil {
		return nil, err
	}
	return h.presign(ctx, id, in.Body.Filename, in.Body.Extension)
}

func (h *Handler) PresignByID(ctx context.Context, in *PresignIDInput) (*PresignOutput, error) {
	rs, err := h.load(ctx, in.ID)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	if err := h.validateUpload(ctx, rs, in.Password, in.Body.Extension, in.Body.Size); err != nil {
		return nil, err
	}
	return h.presign(ctx, in.ID, in.Body.Filename, in.Body.Extension)
}

func (h *Handler) presign(ctx context.Context, reverseShareID, filename, ext string) (*PresignOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	obj := objectPrefixReverseShare + reverseShareID + "/" + time.Now().UTC().Format("20060102150405") + "-" + hex.EncodeToString(b) + "." + ext
	url, err := h.S3.PresignPut(ctx, obj)
	if err != nil {
		return nil, apperr.Internal("presign: " + err.Error())
	}
	out := &PresignOutput{}
	out.Body.URL = url
	out.Body.ObjectName = obj
	out.Body.ExpiresIn = int(h.S3.TTL.Seconds())
	return out, nil
}

// -----------------------------------------------------------------------------
// Register file
// -----------------------------------------------------------------------------

type RegisterFileAliasInput struct {
	Alias    string `path:"alias"`
	Password string `query:"password"`
	Body     struct {
		Name          string  `json:"name" required:"true"`
		Description   *string `json:"description,omitempty"`
		Extension     string  `json:"extension" required:"true"`
		Size          int64   `json:"size" required:"true"`
		ObjectName    string  `json:"objectName" required:"true"`
		UploaderEmail *string `json:"uploaderEmail,omitempty"`
		UploaderName  *string `json:"uploaderName,omitempty"`
	}
}
type RegisterFileIDInput struct {
	ID       string `path:"id"`
	Password string `query:"password"`
	Body     struct {
		Name          string  `json:"name" required:"true"`
		Description   *string `json:"description,omitempty"`
		Extension     string  `json:"extension" required:"true"`
		Size          int64   `json:"size" required:"true"`
		ObjectName    string  `json:"objectName" required:"true"`
		UploaderEmail *string `json:"uploaderEmail,omitempty"`
		UploaderName  *string `json:"uploaderName,omitempty"`
	}
}
// RSFileOutput mirrors the frontend's `RegisterFileUpload201 = { file:
// ReverseShareFile }`. `size` is a stringified int64 (BigInt parity with the
// Prisma Node backend) so the web client can render large file sizes without
// JavaScript number-precision loss.
type RSFileOutput struct {
	Body struct {
		File rsFileView `json:"file"`
	}
}

type rsFileView struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Description   *string            `json:"description"`
	Extension     string             `json:"extension"`
	Size          dbtypes.BigIntStr  `json:"size"`
	ObjectName    string             `json:"objectName"`
	UploaderEmail *string            `json:"uploaderEmail"`
	UploaderName  *string            `json:"uploaderName"`
	CreatedAt     dbtypes.PrismaTime `json:"createdAt"`
	UpdatedAt     dbtypes.PrismaTime `json:"updatedAt"`
}

func (h *Handler) RegisterFileByAlias(ctx context.Context, in *RegisterFileAliasInput) (*RSFileOutput, error) {
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	rs, err := h.load(ctx, id)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	if err := h.validateUpload(ctx, rs, in.Password, in.Body.Extension, &in.Body.Size); err != nil {
		return nil, err
	}
	if !belongsToReverseShare(id, in.Body.ObjectName) {
		return nil, apperr.Forbidden(errObjectNotInShare)
	}
	return h.insertFile(ctx, id, in.Body.Name, in.Body.Description, in.Body.Extension, in.Body.Size,
		in.Body.ObjectName, in.Body.UploaderEmail, in.Body.UploaderName)
}

func (h *Handler) RegisterFileByID(ctx context.Context, in *RegisterFileIDInput) (*RSFileOutput, error) {
	rs, err := h.load(ctx, in.ID)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	if err := h.validateUpload(ctx, rs, in.Password, in.Body.Extension, &in.Body.Size); err != nil {
		return nil, err
	}
	if !belongsToReverseShare(in.ID, in.Body.ObjectName) {
		return nil, apperr.Forbidden(errObjectNotInShare)
	}
	return h.insertFile(ctx, in.ID, in.Body.Name, in.Body.Description, in.Body.Extension, in.Body.Size,
		in.Body.ObjectName, in.Body.UploaderEmail, in.Body.UploaderName)
}

// belongsToReverseShare returns true when the supplied S3 object name
// sits under `reverse-shares/<id>/`. PresignPut / MultipartCreate mint
// keys with exactly that prefix; we enforce it on every anonymous
// callback that takes an `objectName` so an attacker can't register a
// file row against — or finalise a multipart upload against — an
// arbitrary key elsewhere in the bucket.
func belongsToReverseShare(reverseShareID, objectName string) bool {
	if reverseShareID == "" {
		return false
	}
	return strings.HasPrefix(objectName, objectPrefixReverseShare+reverseShareID+"/")
}

func (h *Handler) insertFile(ctx context.Context, reverseShareID, name string, desc *string, ext string, size int64, obj string, email, uploader *string) (*RSFileOutput, error) {
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err := h.DB.ExecContext(ctx, `
		INSERT INTO reverse_share_files (id, name, description, extension, size, objectName, uploaderEmail, uploaderName, reverseShareId, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, name, desc, ext, size, obj, email, uploader, reverseShareID, now, now)
	if err != nil {
		return nil, apperr.Internal("register file: " + err.Error())
	}
	out := &RSFileOutput{}
	out.Body.File = rsFileView{
		ID:            id,
		Name:          name,
		Description:   desc,
		Extension:     ext,
		Size:          dbtypes.BigIntStr(size),
		ObjectName:    obj,
		UploaderEmail: email,
		UploaderName:  uploader,
		CreatedAt:     dbtypes.PrismaTime{Time: now},
		UpdatedAt:     dbtypes.PrismaTime{Time: now},
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Password check (separate endpoint for the modal)
// -----------------------------------------------------------------------------

type CheckPasswordInput struct {
	ID   string `path:"id"`
	Body struct {
		Password string `json:"password" required:"true"`
	}
}
type CheckPasswordOutput struct {
	Body struct {
		Valid bool `json:"valid"`
	}
}

func (h *Handler) CheckPassword(ctx context.Context, in *CheckPasswordInput) (*CheckPasswordOutput, error) {
	rs, err := h.load(ctx, in.ID)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	out := &CheckPasswordOutput{}
	if rs.Password == nil || *rs.Password == "" {
		out.Body.Valid = true
		return out, nil
	}
	out.Body.Valid = auth.VerifyPassword(in.Body.Password, *rs.Password)
	return out, nil
}

// -----------------------------------------------------------------------------
// Multipart
// -----------------------------------------------------------------------------

type MpCreateAliasInput struct {
	Alias    string `path:"alias"`
	Password string `query:"password"`
	Body     struct {
		Filename  string `json:"filename" required:"true"`
		Extension string `json:"extension" required:"true"`
	}
}
type MpCreateOutput struct {
	Body struct {
		UploadID   string `json:"uploadId"`
		ObjectName string `json:"objectName"`
		Message    string `json:"message"`
	}
}

func (h *Handler) MultipartCreate(ctx context.Context, in *MpCreateAliasInput) (*MpCreateOutput, error) {
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	rs, err := h.load(ctx, id)
	if err != nil {
		return nil, apperr.NotFound(errReverseShareNotFound)
	}
	if err := h.validateUpload(ctx, rs, in.Password, in.Body.Extension, nil); err != nil {
		return nil, err
	}
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	obj := objectPrefixReverseShare + id + "/" + time.Now().UTC().Format("20060102150405") + "-" + hex.EncodeToString(b) + "." + in.Body.Extension
	resp, err := h.S3.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(obj),
	})
	if err != nil {
		return nil, apperr.Internal("create multipart: " + err.Error())
	}
	out := &MpCreateOutput{}
	out.Body.UploadID = aws.ToString(resp.UploadId)
	out.Body.ObjectName = obj
	out.Body.Message = "ok"
	return out, nil
}

type MpPartInput struct {
	Alias      string `path:"alias"`
	UploadID   string `query:"uploadId"`
	ObjectName string `query:"objectName"`
	PartNumber int32  `query:"partNumber"`
	Password   string `query:"password"`
}
type MpPartOutput struct {
	Body struct {
		URL string `json:"url"`
	}
}

func (h *Handler) MultipartPart(ctx context.Context, in *MpPartInput) (*MpPartOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(in.ObjectName, objectPrefixReverseShare+id+"/") {
		return nil, apperr.BadRequest("invalid objectName")
	}
	req, err := h.S3.PubPresigner.PresignUploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(h.S3.Bucket),
		Key:        aws.String(in.ObjectName),
		UploadId:   aws.String(in.UploadID),
		PartNumber: aws.Int32(in.PartNumber),
	}, s3.WithPresignExpires(h.S3.TTL))
	if err != nil {
		return nil, apperr.Internal("presign part: " + err.Error())
	}
	out := &MpPartOutput{}
	out.Body.URL = req.URL
	return out, nil
}

type MpCompleteInput struct {
	Alias    string `path:"alias"`
	Password string `query:"password"`
	Body     struct {
		UploadID   string   `json:"uploadId" required:"true"`
		ObjectName string   `json:"objectName" required:"true"`
		Parts      []RSPart `json:"parts" required:"true"`
	}
}

// RSPart accepts the same multi-casing shape produced by Uppy's
// @uppy/aws-s3 plugin (see file.FilePart for the full rationale). Huma
// rejects unknown properties by default, so we have to declare each
// casing — including the `content-length` Uppy adds for upload-progress
// bookkeeping — even though only PartNumber + ETag get used downstream.
// `content-length` is `any` because Uppy ships it as a number, string,
// or null depending on the upstream Content-Length header.
// `x-request-id` is the AWS request-ID header Uppy mirrors back per
// part (added in recent @uppy/aws-s3 releases); we accept it purely
// so huma's strict schema doesn't 422 the multipart complete.
type RSPart struct {
	PartNumber      int32  `json:"PartNumber,omitempty"`
	ETag            string `json:"ETag,omitempty"`
	PartNumberLower int32  `json:"partNumber,omitempty"`
	ETagLower       string `json:"etag,omitempty"`
	ContentLength   any    `json:"content-length,omitempty"`
	XRequestID      string `json:"x-request-id,omitempty"`
}

func (p RSPart) num() int32 {
	if p.PartNumber != 0 {
		return p.PartNumber
	}
	return p.PartNumberLower
}

func (p RSPart) etag() string {
	if p.ETag != "" {
		return p.ETag
	}
	return p.ETagLower
}

func (h *Handler) MultipartComplete(ctx context.Context, in *MpCompleteInput) (*RSMsgOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	// Resolve the alias and confirm the supplied objectName belongs to
	// it. The alias also gates whether the reverse share accepts
	// uploads at all (matching what MultipartCreate does on the same
	// route).
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	if !belongsToReverseShare(id, in.Body.ObjectName) {
		return nil, apperr.Forbidden(errObjectNotInShare)
	}
	parts := make([]s3types.CompletedPart, len(in.Body.Parts))
	for i, p := range in.Body.Parts {
		etag := p.etag()
		num := p.num()
		parts[i] = s3types.CompletedPart{ETag: &etag, PartNumber: &num}
	}
	_, err = h.S3.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(h.S3.Bucket),
		Key:             aws.String(in.Body.ObjectName),
		UploadId:        aws.String(in.Body.UploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return nil, apperr.Internal("complete multipart: " + err.Error())
	}
	// SECURITY (L4): the reverse share advertises rs.MaxFileSize and
	// the global maxFileSize at presign time, but a multipart caller
	// can stream past whatever they claimed. HEAD the object now and
	// drop it if the real size violates either limit. Same delete-on-
	// reject pattern as file.MultipartComplete — refusal alone would
	// leave the oversized object sitting in the bucket.
	if err := h.enforceMultipartSize(ctx, id, in.Body.ObjectName); err != nil {
		return nil, err
	}
	out := &RSMsgOutput{}
	out.Body.Message = "ok"
	return out, nil
}

// enforceMultipartSize compares the just-completed object's true size
// against both rs.maxFileSize (per-reverse-share) and the global
// maxFileSize (app_configs). Oversized objects are deleted before we
// return the error so the bucket can't accumulate junk from rejected
// uploads.
func (h *Handler) enforceMultipartSize(ctx context.Context, reverseShareID, objectName string) error {
	head, err := h.S3.Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(objectName),
	})
	if err != nil {
		_, _ = h.S3.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(h.S3.Bucket),
			Key:    aws.String(objectName),
		})
		return apperr.Internal("verify upload size: " + err.Error())
	}
	size := aws.ToInt64(head.ContentLength)

	var perShare sql.NullInt64
	_ = h.DB.QueryRowContext(ctx,
		`SELECT maxFileSize FROM reverse_shares WHERE id = ?`, reverseShareID).Scan(&perShare)
	if perShare.Valid && perShare.Int64 > 0 && size > perShare.Int64 {
		_, _ = h.S3.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(h.S3.Bucket),
			Key:    aws.String(objectName),
		})
		return apperr.BadRequest("uploaded file exceeds this reverse share's file size limit")
	}

	var globalRaw string
	_ = h.DB.GetContext(ctx, &globalRaw, `SELECT value FROM app_configs WHERE key = 'maxFileSize'`)
	if global, err := strconv.ParseInt(globalRaw, 10, 64); err == nil && global > 0 && size > global {
		_, _ = h.S3.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(h.S3.Bucket),
			Key:    aws.String(objectName),
		})
		return apperr.BadRequest("uploaded file exceeds the global maxFileSize limit")
	}
	return nil
}

type MpAbortInput struct {
	Alias    string `path:"alias"`
	Password string `query:"password"`
	Body     struct {
		UploadID   string `json:"uploadId" required:"true"`
		ObjectName string `json:"objectName" required:"true"`
	}
}

func (h *Handler) MultipartAbort(ctx context.Context, in *MpAbortInput) (*RSMsgOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	id, err := h.aliasToID(ctx, in.Alias)
	if err != nil {
		return nil, err
	}
	if !belongsToReverseShare(id, in.Body.ObjectName) {
		return nil, apperr.Forbidden(errObjectNotInShare)
	}
	_, err = h.S3.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(h.S3.Bucket),
		Key:      aws.String(in.Body.ObjectName),
		UploadId: aws.String(in.Body.UploadID),
	})
	if err != nil {
		return nil, apperr.Internal("abort: " + err.Error())
	}
	out := &RSMsgOutput{}
	out.Body.Message = "aborted"
	return out, nil
}

// -----------------------------------------------------------------------------
// Owner-side file management
// -----------------------------------------------------------------------------

type RSFileInput struct{ FileID string `path:"fileId"` }
type RSDownloadOutput struct {
	Body struct {
		URL       string `json:"url"`
		ExpiresIn int    `json:"expiresIn"`
	}
}

func (h *Handler) DownloadFile(ctx context.Context, in *RSFileInput) (*RSDownloadOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var ownerID, obj, name, ext string
	err = h.DB.QueryRowContext(ctx, `
		SELECT rs.creatorId, f.objectName, f.name, f.extension
		FROM reverse_share_files f JOIN reverse_shares rs ON rs.id = f.reverseShareId
		WHERE f.id = ?`, in.FileID).Scan(&ownerID, &obj, &name, &ext)
	if err != nil {
		return nil, apperr.NotFound(errFileNotFound)
	}
	if ownerID != uc.UserID {
		return nil, apperr.Forbidden(errNotYourReverseShare)
	}
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}
	url, err := h.S3.PresignGet(ctx, obj, name+"."+ext)
	if err != nil {
		return nil, apperr.Internal("presign: " + err.Error())
	}
	out := &RSDownloadOutput{}
	out.Body.URL = url
	out.Body.ExpiresIn = int(h.S3.TTL.Seconds())
	return out, nil
}

func (h *Handler) DeleteFile(ctx context.Context, in *RSFileInput) (*RSMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var ownerID, obj string
	err = h.DB.QueryRowContext(ctx, `
		SELECT rs.creatorId, f.objectName
		FROM reverse_share_files f JOIN reverse_shares rs ON rs.id = f.reverseShareId
		WHERE f.id = ?`, in.FileID).Scan(&ownerID, &obj)
	if err != nil {
		return nil, apperr.NotFound(errFileNotFound)
	}
	if ownerID != uc.UserID {
		return nil, apperr.Forbidden(errNotYourReverseShare)
	}
	if h.S3 != nil {
		_ = h.S3.Delete(ctx, obj)
	}
	dbtypes.LogBestEffort(ctx, "reverseshare.reverseshare.delete.from.reverse_share_files.where", h.DB, `DELETE FROM reverse_share_files WHERE id = ?`, in.FileID)
	out := &RSMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

type UpdateFileInput struct {
	FileID string `path:"fileId"`
	Body   struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
}

func (h *Handler) UpdateFile(ctx context.Context, in *UpdateFileInput) (*RSMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	// Confirm ownership via JOIN.
	var ownerID string
	err = h.DB.QueryRowContext(ctx, `
		SELECT rs.creatorId
		FROM reverse_share_files f JOIN reverse_shares rs ON rs.id = f.reverseShareId
		WHERE f.id = ?`, in.FileID).Scan(&ownerID)
	if err != nil {
		return nil, apperr.NotFound(errFileNotFound)
	}
	if ownerID != uc.UserID {
		return nil, apperr.Forbidden(errNotYourReverseShare)
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
	if len(fields) == 0 {
		return nil, apperr.BadRequest("nothing to update")
	}
	fields = append(fields, "updatedAt = CURRENT_TIMESTAMP")
	args = append(args, in.FileID)
	if _, err := h.DB.ExecContext(ctx, "UPDATE reverse_share_files SET "+strings.Join(fields, ", ")+" WHERE id = ?", args...); err != nil {
		return nil, apperr.Internal("update file")
	}
	out := &RSMsgOutput{}
	out.Body.Message = "updated"
	return out, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func (h *Handler) load(ctx context.Context, id string) (ReverseShare, error) {
	var rs ReverseShare
	err := h.DB.GetContext(ctx, &rs, `
		SELECT id, name, description, expiration, maxFiles, maxFileSize, allowedFileTypes, password,
		       pageLayout, isActive, nameFieldRequired, emailFieldRequired, creatorId, createdAt, updatedAt
		FROM reverse_shares WHERE id = ?`, id)
	return rs, err
}


// loadWithRel returns the row plus its alias + uploaded files, which is
// what the admin UI consumes (ReverseShareWithAlias on the TS side).
func (h *Handler) loadWithRel(ctx context.Context, id string) (ReverseShareWithRel, error) {
	rs, err := h.load(ctx, id)
	if err != nil {
		return ReverseShareWithRel{}, err
	}
	out := ReverseShareWithRel{
		ReverseShare: rs,
		HasPassword:  rs.Password != nil && *rs.Password != "",
		// Pre-initialise so an empty result serialises as `[]`, not `null`.
		Files: []ReverseShareFile{},
	}
	// Files for this reverse-share
	_ = h.DB.SelectContext(ctx, &out.Files, `
		SELECT id, name, description, extension, size, objectName, uploaderEmail, uploaderName, createdAt, updatedAt
		FROM reverse_share_files WHERE reverseShareId = ? ORDER BY createdAt ASC`, id)
	// Optional alias
	var a ReverseShareAlias
	if err := h.DB.GetContext(ctx, &a, `
		SELECT id, alias, reverseShareId, createdAt, updatedAt
		FROM reverse_share_aliases WHERE reverseShareId = ?`, id); err == nil {
		out.Alias = &a
	}
	return out, nil
}

func (h *Handler) assertOwner(ctx context.Context, id, userID string) error {
	var owner string
	if err := h.DB.GetContext(ctx, &owner, `SELECT creatorId FROM reverse_shares WHERE id = ?`, id); err != nil {
		return apperr.NotFound(errReverseShareNotFound)
	}
	if owner != userID {
		return apperr.Forbidden(errNotYourReverseShare)
	}
	return nil
}

func (h *Handler) aliasToID(ctx context.Context, alias string) (string, error) {
	var id string
	if err := h.DB.GetContext(ctx, &id, `SELECT reverseShareId FROM reverse_share_aliases WHERE alias = ?`, alias); err != nil {
		return "", apperr.NotFound("alias not found")
	}
	return id, nil
}

// validateUpload reproduces the legacy `assertUploadConstraintsAtPresign`
// + password gate.
func (h *Handler) validateUpload(ctx context.Context, rs ReverseShare, password, extension string, size *int64) error {
	if !rs.IsActive {
		return apperr.Forbidden("Reverse share is inactive")
	}
	if rs.Expiration != nil && rs.Expiration.Before(time.Now()) {
		return apperr.Gone("Reverse share has expired")
	}
	if rs.Password != nil && *rs.Password != "" {
		if password == "" {
			return apperr.Unauthorized("Password required")
		}
		if !auth.VerifyPassword(password, *rs.Password) {
			return apperr.Unauthorized("Invalid password")
		}
	}
	if rs.MaxFiles != nil {
		var n int
		_ = h.DB.GetContext(ctx, &n, `SELECT COUNT(*) FROM reverse_share_files WHERE reverseShareId = ?`, rs.ID)
		if n >= *rs.MaxFiles {
			return apperr.BadRequest("Maximum number of files reached")
		}
	}
	if size != nil && rs.MaxFileSize != nil && *size > *rs.MaxFileSize {
		return apperr.BadRequest("File size exceeds limit")
	}
	if rs.AllowedFileTypes != nil && *rs.AllowedFileTypes != "" {
		allowed := false
		for _, t := range strings.Split(*rs.AllowedFileTypes, ",") {
			if strings.EqualFold(strings.TrimSpace(t), extension) {
				allowed = true
				break
			}
		}
		if !allowed {
			return apperr.BadRequest("File type not allowed")
		}
	}
	return nil
}

// stringOr returns *p when non-nil and non-empty, otherwise def.
func stringOr(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

// -----------------------------------------------------------------------------
// POST /reverse-shares/files/{fileId}/copy
//
// Copy a file that landed in a reverse-share into the owner's own
// `files` table — so they can re-share it like any uploaded file. The
// S3 object is duplicated server-side (CopyObject), not streamed
// through the API.
// -----------------------------------------------------------------------------

type RSCopyOutput struct {
	Body struct {
		FileID     string `json:"fileId"`
		ObjectName string `json:"objectName"`
	}
}

func (h *Handler) CopyFile(ctx context.Context, in *RSFileInput) (*RSCopyOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}

	// Load source + ownership check.
	var ownerID, srcObj, name, ext string
	var size int64
	err = h.DB.QueryRowContext(ctx, `
		SELECT rs.creatorId, f.objectName, f.name, f.extension, f.size
		FROM reverse_share_files f JOIN reverse_shares rs ON rs.id = f.reverseShareId
		WHERE f.id = ?`, in.FileID).Scan(&ownerID, &srcObj, &name, &ext, &size)
	if err != nil {
		return nil, apperr.NotFound(errFileNotFound)
	}
	if ownerID != uc.UserID {
		return nil, apperr.Forbidden(errNotYourReverseShare)
	}
	if h.S3 == nil {
		return nil, apperr.Internal(errS3NotConfigured)
	}

	// Server-side copy. CopySource expects "<bucket>/<key>" with URL-escaped key.
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	dstObj := uc.UserID + "/" + time.Now().UTC().Format("20060102150405") + "-" + hex.EncodeToString(b) + "." + ext
	_, err = h.S3.Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(h.S3.Bucket),
		Key:        aws.String(dstObj),
		CopySource: aws.String(h.S3.Bucket + "/" + srcObj),
	})
	if err != nil {
		return nil, apperr.Internal("copy object: " + err.Error())
	}

	// Insert into files. We use sql import via *sqlx.DB; the SQL is the
	// same one the file module's RegisterFile uses.
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO files (id, name, description, extension, size, objectName, userId, folderId, createdAt, updatedAt)
		VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?)`,
		id, name, ext, size, dstObj, uc.UserID, now, now)
	if err != nil {
		return nil, apperr.Internal("insert file: " + err.Error())
	}
	out := &RSCopyOutput{}
	out.Body.FileID = id
	out.Body.ObjectName = dstObj
	return out, nil
}
