// Package embed exposes /embed/:id — used by the frontend to embed images
// (e.g. share previews) without a presigned URL roundtrip. The handler
// streams the bytes from S3 with the right Content-Type.
package embed

import (
	"context"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
	"github.com/sixmon/palmr/apps/server-go/internal/storage"
)

type Handler struct {
	DB *sqlx.DB
	S3 *storage.S3
}

// RegisterPlain attaches /embed/{id} as a chi route. Huma isn't a good
// fit for raw streaming responses with content-type sniffing.
func (h *Handler) RegisterPlain(r chi.Router) {
	r.Get("/embed/{id}", h.serve)
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var obj, ext string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT objectName, extension FROM files WHERE id = ?`, id).Scan(&obj, &ext); err != nil {
		http.NotFound(w, r)
		return
	}
	if h.S3 == nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "S3 not configured")
		return
	}
	out, err := h.S3.Client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(obj),
	})
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "fetch: "+err.Error())
		return
	}
	defer out.Body.Close()
	if ct := out.ContentType; ct != nil && *ct != "" {
		w.Header().Set("Content-Type", *ct)
	} else {
		w.Header().Set("Content-Type", mimeForExt(ext))
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.Copy(w, out.Body)
}

func mimeForExt(ext string) string {
	switch ext {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "svg":
		return "image/svg+xml"
	case "pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}
