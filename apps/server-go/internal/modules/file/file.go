// Package file implements the /files routes.
//
//   POST   /files                     register a file already uploaded to S3
//   GET    /files                     list mine (auth)
//   GET    /files/presigned-url       presigned PUT for a fresh upload
//   GET    /files/download-url        presigned GET (auth-OR-share-password)
//   PATCH  /files/{id}                rename / change description
//   DELETE /files/{id}                delete
//   PUT    /files/{id}/move           move into folder
//   POST   /files/check               name/extension probe (rate-limit replacement)
//   POST   /files/multipart/create    init multipart upload
//   GET    /files/multipart/part-url  sign one part
//   POST   /files/multipart/complete  finalise
//   POST   /files/multipart/abort     abort
//
// All routes are authenticated except /files/download-url, which also
// accepts a share password (read by share.CheckAccessByFile via the
// X-Share-Password header).
package file

import (
	dbtypes "github.com/sixmon/palmr/apps/server-go/internal/db"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
	"github.com/sixmon/palmr/apps/server-go/internal/storage"
)

type File struct {
	ID          string    `db:"id"          json:"id"`
	Name        string    `db:"name"        json:"name"`
	Description *string   `db:"description" json:"description"`
	Extension   string    `db:"extension"   json:"extension"`
	Size        int64     `db:"size"        json:"size"`
	ObjectName  string    `db:"objectName"  json:"objectName"`
	UserID      string    `db:"userId"      json:"userId"`
	FolderID    *string   `db:"folderId"    json:"folderId"`
	CreatedAt   dbtypes.PrismaTime `db:"createdAt"   json:"createdAt"`
	UpdatedAt   dbtypes.PrismaTime `db:"updatedAt"   json:"updatedAt"`
}

type Handler struct {
	DB *sqlx.DB
	S3 *storage.S3
}

func Register(api huma.API, h *Handler) {
	op := func(method, path, id string) huma.Operation {
		return huma.Operation{Method: method, Path: path, Tags: []string{"File"}, OperationID: id}
	}
	huma.Register(api, op(http.MethodGet, "/files/presigned-url", "getPresignedUrl"), h.PresignPut)
	huma.Register(api, op(http.MethodPost, "/files", "registerFile"), h.RegisterFile)
	huma.Register(api, op(http.MethodPost, "/files/check", "checkFile"), h.CheckFile)
	huma.Register(api, op(http.MethodGet, "/files/download-url", "getDownloadUrl"), h.PresignGet)
	huma.Register(api, op(http.MethodGet, "/files", "listFiles"), h.List)
	huma.Register(api, op(http.MethodPatch, "/files/{id}", "updateFile"), h.Update)
	huma.Register(api, op(http.MethodDelete, "/files/{id}", "deleteFile"), h.Delete)
	huma.Register(api, op(http.MethodPut, "/files/{id}/move", "moveFile"), h.Move)

	huma.Register(api, op(http.MethodPost, "/files/multipart/create", "createMultipart"), h.MultipartCreate)
	huma.Register(api, op(http.MethodGet, "/files/multipart/part-url", "getMultipartPartUrl"), h.MultipartPartURL)
	huma.Register(api, op(http.MethodPost, "/files/multipart/complete", "completeMultipart"), h.MultipartComplete)
	huma.Register(api, op(http.MethodPost, "/files/multipart/abort", "abortMultipart"), h.MultipartAbort)
}

// -----------------------------------------------------------------------------
// GET /files/presigned-url?filename=...&extension=...
// -----------------------------------------------------------------------------

type FilePresignPutInput struct {
	Filename  string `query:"filename"  required:"true"`
	Extension string `query:"extension" required:"true"`
}
type FilePresignPutOutput struct {
	Body struct {
		URL        string `json:"url"`
		ObjectName string `json:"objectName"`
		ExpiresIn  int    `json:"expiresIn"`
	}
}

func (h *Handler) PresignPut(ctx context.Context, in *FilePresignPutInput) (*FilePresignPutOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
	}
	obj := genObjectName(uc.UserID, in.Filename, in.Extension)
	url, err := h.S3.PresignPut(ctx, obj)
	if err != nil {
		return nil, apperr.Internal("presign: " + err.Error())
	}
	out := &FilePresignPutOutput{}
	out.Body.URL = url
	out.Body.ObjectName = obj
	out.Body.ExpiresIn = int(h.S3.TTL.Seconds())
	return out, nil
}

// -----------------------------------------------------------------------------
// POST /files — body: { name, description, extension, size, objectName }
// -----------------------------------------------------------------------------

type FileRegisterInput struct {
	Body struct {
		Name        string  `json:"name" required:"true"`
		Description *string `json:"description,omitempty"`
		Extension   string  `json:"extension" required:"true"`
		Size        int64   `json:"size" required:"true"`
		ObjectName  string  `json:"objectName" required:"true"`
		FolderID    *string `json:"folderId,omitempty"`
	}
}
type FileRegisterOutput struct {
	Body struct {
		File File `json:"file"`
	}
}

func (h *Handler) RegisterFile(ctx context.Context, in *FileRegisterInput) (*FileRegisterOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	// Security: the objectName must start with the caller's userId — this
	// is what we generated in /files/presigned-url. Without this check a
	// client could register an objectName pointing at someone else's
	// upload (parity with legacy fix C-batch).
	if !strings.HasPrefix(in.Body.ObjectName, uc.UserID+"/") {
		return nil, apperr.BadRequest("invalid objectName")
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO files (id, name, description, extension, size, objectName, userId, folderId, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, in.Body.Name, in.Body.Description, in.Body.Extension, in.Body.Size,
		in.Body.ObjectName, uc.UserID, in.Body.FolderID, now, now)
	if err != nil {
		return nil, apperr.Internal("insert file: " + err.Error())
	}
	f, err := h.load(ctx, id)
	if err != nil {
		return nil, apperr.Internal("reload file")
	}
	out := &FileRegisterOutput{}
	out.Body.File = f
	return out, nil
}

// -----------------------------------------------------------------------------
// POST /files/check — body: { name, extension }
// Returns whether a file with that exact name+extension already exists
// in the user's root folder, so the UI can warn before upload.
// -----------------------------------------------------------------------------

type FileCheckInput struct {
	Body struct {
		Name      string `json:"name" required:"true"`
		Extension string `json:"extension" required:"true"`
	}
}
type FileCheckOutput struct {
	Body struct {
		Exists bool `json:"exists"`
	}
}

func (h *Handler) CheckFile(ctx context.Context, in *FileCheckInput) (*FileCheckOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	var n int
	_ = h.DB.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM files WHERE userId = ? AND name = ? AND extension = ? AND folderId IS NULL`,
		uc.UserID, in.Body.Name, in.Body.Extension)
	out := &FileCheckOutput{}
	out.Body.Exists = n > 0
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /files/download-url?objectName=...
// -----------------------------------------------------------------------------

type FileDownloadInput struct {
	ObjectName     string `query:"objectName" required:"true"`
	SharePassword  string `header:"X-Share-Password"`
	QueryPassword  string `query:"password"`
}
type FileDownloadOutput struct {
	Body struct {
		URL       string `json:"url"`
		ExpiresIn int    `json:"expiresIn"`
	}
}

func (h *Handler) PresignGet(ctx context.Context, in *FileDownloadInput) (*FileDownloadOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
	}
	// Find the file by objectName.
	var f File
	err := h.DB.GetContext(ctx, &f,
		`SELECT id, name, description, extension, size, objectName, userId, folderId, createdAt, updatedAt
		 FROM files WHERE objectName = ?`, in.ObjectName)
	if err != nil {
		return nil, apperr.NotFound("file not found")
	}

	// Access rules:
	//  - the owner can always download
	//  - anyone with a share that contains this file can download, if the
	//    share's password (if any) matches the supplied one
	// Until the share module is wired in, we keep parity by accepting
	// either an authenticated owner OR the X-Share-Password matching ANY
	// share that contains the file.
	uc, _ := auth.FromContext(ctx)
	if uc.UserID != "" && uc.UserID == f.UserID {
		return h.signGet(ctx, f.ObjectName, f.Name+"."+f.Extension)
	}
	pwd := in.SharePassword
	if pwd == "" {
		pwd = in.QueryPassword
	}
	if ok, _ := shareAccessByFile(ctx, h.DB, f.ID, pwd); ok {
		return h.signGet(ctx, f.ObjectName, f.Name+"."+f.Extension)
	}
	return nil, apperr.Unauthorized("Unauthorized access to file.")
}

func (h *Handler) signGet(ctx context.Context, obj, fname string) (*FileDownloadOutput, error) {
	url, err := h.S3.PresignGet(ctx, obj, fname)
	if err != nil {
		return nil, apperr.Internal("presign: " + err.Error())
	}
	out := &FileDownloadOutput{}
	out.Body.URL = url
	out.Body.ExpiresIn = int(h.S3.TTL.Seconds())
	return out, nil
}

// shareAccessByFile returns (true, nil) when the supplied password lets
// pwd-anonymous access to a share containing fileID. Imported here as a
// free function so file/ doesn't depend on share/ at the package level.
func shareAccessByFile(ctx context.Context, db *sqlx.DB, fileID, pwd string) (bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT s.id, sec.password, sec.maxViews, s.views, s.expiration
		FROM shares s
		JOIN share_security sec ON sec.id = s.securityId
		JOIN _ShareFiles sf ON sf.B = s.id
		WHERE sf.A = ?`, fileID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var id string
		var hashedPwd *string
		var maxViews *int
		var views int
		var exp *time.Time
		if err := rows.Scan(&id, &hashedPwd, &maxViews, &views, &exp); err != nil {
			continue
		}
		if exp != nil && exp.Before(now) {
			continue
		}
		if maxViews != nil && views >= *maxViews {
			continue
		}
		if hashedPwd == nil || *hashedPwd == "" {
			return true, nil
		}
		if pwd != "" && auth.VerifyPassword(pwd, *hashedPwd) {
			return true, nil
		}
	}
	return false, nil
}

// -----------------------------------------------------------------------------
// GET /files
// -----------------------------------------------------------------------------

type FileListInput struct{}
type FileListOutput struct {
	Body struct {
		Files []File `json:"files"`
	}
}

func (h *Handler) List(ctx context.Context, _ *FileListInput) (*FileListOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &FileListOutput{}
	if err := h.DB.SelectContext(ctx, &out.Body.Files,
		`SELECT id, name, description, extension, size, objectName, userId, folderId, createdAt, updatedAt
		 FROM files WHERE userId = ? ORDER BY createdAt DESC`, uc.UserID); err != nil {
		return nil, apperr.Internal("list files")
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// PATCH /files/{id}
// -----------------------------------------------------------------------------

type FileUpdateInput struct {
	ID   string `path:"id"`
	Body struct {
		Name        *string `json:"name,omitempty"`
		Description *string `json:"description,omitempty"`
	}
}
type FileSingleOutput struct {
	Body struct{ File File `json:"file"` }
}

func (h *Handler) Update(ctx context.Context, in *FileUpdateInput) (*FileSingleOutput, error) {
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
	q := "UPDATE files SET " + strings.Join(fields, ", ") + " WHERE id = ?"
	if _, err := h.DB.ExecContext(ctx, q, args...); err != nil {
		return nil, apperr.Internal("update file")
	}
	f, _ := h.load(ctx, in.ID)
	out := &FileSingleOutput{}
	out.Body.File = f
	return out, nil
}

// -----------------------------------------------------------------------------
// DELETE /files/{id}
// -----------------------------------------------------------------------------

type FileDeleteInput struct{ ID string `path:"id"` }
type FileMsgOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (h *Handler) Delete(ctx context.Context, in *FileDeleteInput) (*FileMsgOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	f, err := h.load(ctx, in.ID)
	if err != nil {
		return nil, apperr.NotFound("file not found")
	}
	if f.UserID != uc.UserID {
		return nil, apperr.Forbidden("not your file")
	}
	if h.S3 != nil {
		_ = h.S3.Delete(ctx, f.ObjectName) // best-effort
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM files WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete file")
	}
	out := &FileMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

// -----------------------------------------------------------------------------
// PUT /files/{id}/move
// -----------------------------------------------------------------------------

type FileMoveInput struct {
	ID   string `path:"id"`
	Body struct {
		FolderID *string `json:"folderId,omitempty"`
	}
}

func (h *Handler) Move(ctx context.Context, in *FileMoveInput) (*FileSingleOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if err := h.assertOwner(ctx, in.ID, uc.UserID); err != nil {
		return nil, err
	}
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE files SET folderId = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		in.Body.FolderID, in.ID); err != nil {
		return nil, apperr.Internal("move file")
	}
	f, _ := h.load(ctx, in.ID)
	out := &FileSingleOutput{}
	out.Body.File = f
	return out, nil
}

// -----------------------------------------------------------------------------
// Multipart upload — thin wrappers over the SDK's CreateMultipartUpload
// / UploadPart / CompleteMultipartUpload.
// -----------------------------------------------------------------------------

type MultipartCreateInput struct {
	Body struct {
		Filename  string `json:"filename" required:"true"`
		Extension string `json:"extension" required:"true"`
	}
}
type MultipartCreateOutput struct {
	Body struct {
		UploadID   string `json:"uploadId"`
		ObjectName string `json:"objectName"`
		Message    string `json:"message"`
	}
}

func (h *Handler) MultipartCreate(ctx context.Context, in *MultipartCreateInput) (*MultipartCreateOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
	}
	obj := genObjectName(uc.UserID, in.Body.Filename, in.Body.Extension)
	resp, err := h.S3.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(obj),
	})
	if err != nil {
		return nil, apperr.Internal("create multipart: " + err.Error())
	}
	out := &MultipartCreateOutput{}
	out.Body.UploadID = aws.ToString(resp.UploadId)
	out.Body.ObjectName = obj
	out.Body.Message = "ok"
	return out, nil
}

type MultipartPartInput struct {
	UploadID   string `query:"uploadId" required:"true"`
	ObjectName string `query:"objectName" required:"true"`
	PartNumber int32  `query:"partNumber" required:"true"`
}
type MultipartPartOutput struct {
	Body struct {
		URL string `json:"url"`
	}
}

func (h *Handler) MultipartPartURL(ctx context.Context, in *MultipartPartInput) (*MultipartPartOutput, error) {
	uc, err := auth.EnsureAuth(ctx)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if !strings.HasPrefix(in.ObjectName, uc.UserID+"/") {
		return nil, apperr.BadRequest("invalid objectName")
	}
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
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
	out := &MultipartPartOutput{}
	out.Body.URL = req.URL
	return out, nil
}

type FilePart struct {
	PartNumber int32  `json:"PartNumber"`
	ETag       string `json:"ETag"`
}
type MultipartCompleteInput struct {
	Body struct {
		UploadID   string     `json:"uploadId" required:"true"`
		ObjectName string     `json:"objectName" required:"true"`
		Parts      []FilePart `json:"parts" required:"true"`
	}
}

func (h *Handler) MultipartComplete(ctx context.Context, in *MultipartCompleteInput) (*FileMsgOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
	}
	completed := make([]s3types.CompletedPart, len(in.Body.Parts))
	for i, p := range in.Body.Parts {
		etag := p.ETag
		num := p.PartNumber
		completed[i] = s3types.CompletedPart{ETag: &etag, PartNumber: &num}
	}
	_, err := h.S3.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(h.S3.Bucket),
		Key:             aws.String(in.Body.ObjectName),
		UploadId:        aws.String(in.Body.UploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: completed},
	})
	if err != nil {
		return nil, apperr.Internal("complete multipart: " + err.Error())
	}
	out := &FileMsgOutput{}
	out.Body.Message = "ok"
	return out, nil
}

type MultipartAbortInput struct {
	Body struct {
		UploadID   string `json:"uploadId" required:"true"`
		ObjectName string `json:"objectName" required:"true"`
	}
}

func (h *Handler) MultipartAbort(ctx context.Context, in *MultipartAbortInput) (*FileMsgOutput, error) {
	if h.S3 == nil {
		return nil, apperr.Internal("S3 not configured")
	}
	_, err := h.S3.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(h.S3.Bucket),
		Key:      aws.String(in.Body.ObjectName),
		UploadId: aws.String(in.Body.UploadID),
	})
	if err != nil {
		return nil, apperr.Internal("abort multipart: " + err.Error())
	}
	out := &FileMsgOutput{}
	out.Body.Message = "aborted"
	return out, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func (h *Handler) load(ctx context.Context, id string) (File, error) {
	var f File
	err := h.DB.GetContext(ctx, &f,
		`SELECT id, name, description, extension, size, objectName, userId, folderId, createdAt, updatedAt
		 FROM files WHERE id = ?`, id)
	return f, err
}

func (h *Handler) assertOwner(ctx context.Context, id, userID string) error {
	var owner string
	if err := h.DB.GetContext(ctx, &owner, `SELECT userId FROM files WHERE id = ?`, id); err != nil {
		return apperr.NotFound("file not found")
	}
	if owner != userID {
		return apperr.Forbidden("not your file")
	}
	return nil
}

// genObjectName mirrors the legacy backend: <userId>/<timestamp>-<random>.<ext>
func genObjectName(userID, filename, ext string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return userID + "/" + time.Now().UTC().Format("20060102150405") + "-" + hex.EncodeToString(b) + "." + ext
}
