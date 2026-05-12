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

// DiskOutput matches the frontend `DiskSpaceInfo` (apps/web/.../app/types.ts):
// values in GB (float, 2-decimal precision is enough) and a boolean indicating
// whether the user still has room for *any* upload. The frontend's storage
// panel reads these fields verbatim — no `success`/`data` envelope here.
type DiskOutput struct {
	Body struct {
		DiskSizeGB      float64 `json:"diskSizeGB"`
		DiskUsedGB      float64 `json:"diskUsedGB"`
		DiskAvailableGB float64 `json:"diskAvailableGB"`
		UploadAllowed   bool    `json:"uploadAllowed"`
	}
}

const bytesPerGB = 1024 * 1024 * 1024

func bytesToGB(b int64) float64 {
	// Two-decimal rounding for parity with the legacy Node backend, which
	// also rounded on the way out.
	gb := float64(b) / float64(bytesPerGB)
	return float64(int64(gb*100+0.5)) / 100
}

func (h *Handler) DiskSpace(ctx context.Context, _ *struct{}) (*DiskOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var used int64
	_ = h.DB.GetContext(ctx, &used, `SELECT COALESCE(SUM(size), 0) FROM files WHERE userId = ?`, uc.UserID)
	var total int64
	_ = h.DB.GetContext(ctx, &total, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxTotalStoragePerUser'`)
	if total == 0 {
		total = 10737418240 // 10 GiB default — keep in sync with legacy seed.
	}
	available := total - used
	if available < 0 {
		available = 0
	}
	out := &DiskOutput{}
	out.Body.DiskSizeGB = bytesToGB(total)
	out.Body.DiskUsedGB = bytesToGB(used)
	out.Body.DiskAvailableGB = bytesToGB(available)
	out.Body.UploadAllowed = available > 0
	return out, nil
}

type StorageCheckInput struct {
	// Legacy Node API used `?fileSize=` (see frontend
	// `CheckUploadAllowedParams.fileSize`); accept both for compat.
	FileSize int64 `query:"fileSize"`
	Size     int64 `query:"size"`
}

// StorageCheckOutput mirrors `CheckUploadAllowed200` on the frontend — same
// fields as `DiskSpaceInfo` plus a `fileSizeInfo` breakdown of the requested
// size in different units.
type StorageCheckOutput struct {
	Body struct {
		DiskSizeGB      float64 `json:"diskSizeGB"`
		DiskUsedGB      float64 `json:"diskUsedGB"`
		DiskAvailableGB float64 `json:"diskAvailableGB"`
		UploadAllowed   bool    `json:"uploadAllowed"`
		FileSizeInfo    struct {
			Bytes int64   `json:"bytes"`
			KB    float64 `json:"kb"`
			MB    float64 `json:"mb"`
			GB    float64 `json:"gb"`
		} `json:"fileSizeInfo"`
	}
}

func (h *Handler) CheckUpload(ctx context.Context, in *StorageCheckInput) (*StorageCheckOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	size := in.FileSize
	if size == 0 {
		size = in.Size
	}
	out := &StorageCheckOutput{}
	var maxFile, maxTotal int64
	_ = h.DB.GetContext(ctx, &maxFile, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxFileSize'`)
	_ = h.DB.GetContext(ctx, &maxTotal, `SELECT CAST(value AS INTEGER) FROM app_configs WHERE key = 'maxTotalStoragePerUser'`)
	if maxTotal == 0 {
		maxTotal = 10737418240
	}
	var used int64
	_ = h.DB.GetContext(ctx, &used, `SELECT COALESCE(SUM(size), 0) FROM files WHERE userId = ?`, uc.UserID)
	available := maxTotal - used
	if available < 0 {
		available = 0
	}
	allowed := true
	if maxFile > 0 && size > maxFile {
		allowed = false
	}
	if size > 0 && size > available {
		allowed = false
	}
	out.Body.DiskSizeGB = bytesToGB(maxTotal)
	out.Body.DiskUsedGB = bytesToGB(used)
	out.Body.DiskAvailableGB = bytesToGB(available)
	out.Body.UploadAllowed = allowed
	out.Body.FileSizeInfo.Bytes = size
	out.Body.FileSizeInfo.KB = float64(size) / 1024
	out.Body.FileSizeInfo.MB = float64(size) / (1024 * 1024)
	out.Body.FileSizeInfo.GB = bytesToGB(size)
	return out, nil
}
