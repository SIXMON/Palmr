// Package storage exposes the legacy /storage/* endpoints:
//   GET /storage/disk-space   — overall storage usage
//   GET /storage/check-upload?size=… — can the user upload this many bytes?
package storage

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
)

type Handler struct{ DB *sqlx.DB }

func Register(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/storage/disk-space",
		Tags: []string{"Storage"}, OperationID: "getDiskSpace",
	}, h.DiskSpace)
	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/storage/check-upload",
		Tags: []string{"Storage"}, OperationID: "checkUpload",
	}, h.CheckUpload)
}

type DiskOutput struct {
	Body struct {
		TotalSpace int64 `json:"totalSpace"`
		UsedSpace  int64 `json:"usedSpace"`
	}
}

func (h *Handler) DiskSpace(ctx context.Context, _ *struct{}) (*DiskOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var used int64
	_ = h.DB.GetContext(ctx, &used, `SELECT COALESCE(SUM(size), 0) FROM files WHERE userId = ?`, uc.UserID)
	out := &DiskOutput{}
	out.Body.UsedSpace = used
	// Total comes from the app_configs `maxTotalStoragePerUser`.
	var total int64
	_ = h.DB.GetContext(ctx, &total, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxTotalStoragePerUser'`)
	if total == 0 {
		total = 10737418240
	}
	out.Body.TotalSpace = total
	return out, nil
}

type StorageCheckInput struct {
	Size int64 `query:"size" required:"true"`
}
type StorageCheckOutput struct {
	Body struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason,omitempty"`
	}
}

func (h *Handler) CheckUpload(ctx context.Context, in *StorageCheckInput) (*StorageCheckOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &StorageCheckOutput{}
	var maxFile, maxTotal int64
	_ = h.DB.GetContext(ctx, &maxFile, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxFileSize'`)
	_ = h.DB.GetContext(ctx, &maxTotal, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxTotalStoragePerUser'`)
	if maxFile > 0 && in.Size > maxFile {
		out.Body.Allowed = false
		out.Body.Reason = "file size exceeds per-file limit"
		return out, nil
	}
	var used int64
	_ = h.DB.GetContext(ctx, &used, `SELECT COALESCE(SUM(size), 0) FROM files WHERE userId = ?`, uc.UserID)
	if maxTotal > 0 && used+in.Size > maxTotal {
		out.Body.Allowed = false
		out.Body.Reason = "quota exceeded"
		return out, nil
	}
	out.Body.Allowed = true
	return out, nil
}
