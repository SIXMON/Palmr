// Package folder implements /folders.
package folder

import (
	dbtypes "github.com/sixmon/palmr/apps/server-go/internal/db"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
)

type Folder struct {
	ID          string    `db:"id"          json:"id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description"`
	ObjectName  string    `db:"objectName"  json:"objectName"`
	ParentID    *string   `db:"parentId"    json:"parentId"`
	UserID      string    `db:"userId"      json:"userId"`
	CreatedAt   dbtypes.PrismaTime `db:"createdAt"   json:"createdAt"`
	UpdatedAt   dbtypes.PrismaTime `db:"updatedAt"   json:"updatedAt"`
}

type Handler struct {
	DB *sqlx.DB
}

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"Folder"}, OperationID: id}
	}
	huma.Register(api, op(http.MethodPost, "/folders", "createFolder"), h.Create)
	huma.Register(api, op(http.MethodGet, "/folders", "listFolders"), h.List)
	huma.Register(api, op(http.MethodPost, "/folders/check", "checkFolder"), h.Check)
	huma.Register(api, op(http.MethodPatch, "/folders/{id}", "updateFolder"), h.Update)
	huma.Register(api, op(http.MethodDelete, "/folders/{id}", "deleteFolder"), h.Delete)
	huma.Register(api, op(http.MethodPut, "/folders/{id}/move", "moveFolder"), h.Move)
}

// -----------------------------------------------------------------------------

type FolderCreateInput struct {
	Body struct {
		Name        string  `json:"name" required:"true"`
		Description *string `json:"description,omitempty"`
		ParentID    *string `json:"parentId,omitempty"`
	}
}
type FolderSingleOutput struct {
	Body struct{ Folder Folder `json:"folder"` }
}
type FolderMsgOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (h *Handler) Create(ctx context.Context, in *FolderCreateInput) (*FolderSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	objectName := "folder/" + uc.UserID + "/" + id // synthetic, never hit S3
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO folders (id, name, description, objectName, parentId, userId, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, in.Body.Name, in.Body.Description, objectName, in.Body.ParentID, uc.UserID, now, now)
	if err != nil {
		return nil, apperr.Internal("insert folder: " + err.Error())
	}
	f, _ := h.load(ctx, id)
	out := &FolderSingleOutput{}
	out.Body.Folder = f
	return out, nil
}

// -----------------------------------------------------------------------------

type FolderListInput struct{}
type FolderListOutput struct {
	Body struct {
		Folders []Folder `json:"folders"`
	}
}

func (h *Handler) List(ctx context.Context, _ *FolderListInput) (*FolderListOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &FolderListOutput{}
	_ = h.DB.SelectContext(ctx, &out.Body.Folders,
		`SELECT id, name, description, objectName, parentId, userId, createdAt, updatedAt
		 FROM folders WHERE userId = ? ORDER BY createdAt DESC`, uc.UserID)
	return out, nil
}

// -----------------------------------------------------------------------------

type FolderCheckInput struct {
	Body struct {
		Name string `json:"name" required:"true"`
	}
}
type FolderCheckOutput struct {
	Body struct {
		Exists bool `json:"exists"`
	}
}

func (h *Handler) Check(ctx context.Context, in *FolderCheckInput) (*FolderCheckOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var n int
	_ = h.DB.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM folders WHERE userId = ? AND name = ? AND parentId IS NULL`,
		uc.UserID, in.Body.Name)
	out := &FolderCheckOutput{}
	out.Body.Exists = n > 0
	return out, nil
}

// -----------------------------------------------------------------------------

type FolderUpdateInput struct {
	ID   string `path:"id"`
	Body struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
}

func (h *Handler) Update(ctx context.Context, in *FolderUpdateInput) (*FolderSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
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
	if len(fields) == 0 {
		return nil, apperr.BadRequest("nothing to update")
	}
	fields = append(fields, "updatedAt = CURRENT_TIMESTAMP")
	args = append(args, in.ID)
	q := "UPDATE folders SET " + strings.Join(fields, ", ") + " WHERE id = ?"
	if _, err := h.DB.ExecContext(ctx, q, args...); err != nil {
		return nil, apperr.Internal("update folder")
	}
	f, _ := h.load(ctx, in.ID)
	out := &FolderSingleOutput{}
	out.Body.Folder = f
	return out, nil
}

// -----------------------------------------------------------------------------

func (h *Handler) Delete(ctx context.Context, in *struct{ ID string `path:"id"` }) (*FolderMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM folders WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete folder")
	}
	out := &FolderMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

// -----------------------------------------------------------------------------

type FolderMoveInput struct {
	ID   string `path:"id"`
	Body struct {
		ParentID *string `json:"parentId,omitempty"`
	}
}

func (h *Handler) Move(ctx context.Context, in *FolderMoveInput) (*FolderSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE folders SET parentId = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		in.Body.ParentID, in.ID); err != nil {
		return nil, apperr.Internal("move folder")
	}
	f, _ := h.load(ctx, in.ID)
	out := &FolderSingleOutput{}
	out.Body.Folder = f
	return out, nil
}

// -----------------------------------------------------------------------------

func (h *Handler) load(ctx context.Context, id string) (Folder, error) {
	var f Folder
	err := h.DB.GetContext(ctx, &f,
		`SELECT id, name, description, objectName, parentId, userId, createdAt, updatedAt
		 FROM folders WHERE id = ?`, id)
	return f, err
}

func (h *Handler) assertOwner(ctx context.Context, id, userID string) error {
	var owner string
	if err := h.DB.GetContext(ctx, &owner, `SELECT userId FROM folders WHERE id = ?`, id); err != nil {
		return apperr.NotFound("folder not found")
	}
	if owner != userID {
		return apperr.Forbidden("not your folder")
	}
	return nil
}
