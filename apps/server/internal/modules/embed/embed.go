// Package embed exposes /embed/:id — used by the frontend to embed images
// (e.g. share previews) without a presigned URL roundtrip. The handler
// streams the bytes from S3 with a safe Content-Type.
//
// SECURITY: this route is anonymous (anyone with a file ID can fetch).
// SVG, HTML, and similar content types execute scripts when rendered
// inline by the browser. To avoid same-origin XSS we:
//
//   * Pin the Content-Type to a safe inline-able image set when the
//     stored extension matches a known-safe image. SVG is explicitly
//     NOT included here — it's served as octet-stream + attachment
//     disposition so the browser downloads rather than renders it.
//   * Set `X-Content-Type-Options: nosniff` so a stored Content-Type
//     of `text/html` (uploaded by a malicious user pretending it's a
//     PNG) can't be sniffed and rendered.
//   * Reflect the request context (`r.Context()`) into the S3 call so
//     a disconnecting client cancels the upstream pull.
package embed

import (
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
	"github.com/sixmon/palmr/apps/server/internal/storage"
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

// safeInlineMime maps the stored file extension to a Content-Type the
// browser is *safe* to render inline. Anything not in this set is
// served as octet-stream + an attachment disposition.
var safeInlineMime = map[string]string{
	"png":  "image/png",
	"jpg":  "image/jpeg",
	"jpeg": "image/jpeg",
	"gif":  "image/gif",
	"webp": "image/webp",
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var obj, name, ext string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT objectName, name, extension FROM files WHERE id = ?`, id).Scan(&obj, &name, &ext); err != nil {
		http.NotFound(w, r)
		return
	}
	if h.S3 == nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "S3 not configured")
		return
	}
	out, err := h.S3.Client.GetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(h.S3.Bucket),
		Key:    aws.String(obj),
	})
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "fetch: "+err.Error())
		return
	}
	defer out.Body.Close()

	ct, inline := safeInlineMime[strings.ToLower(ext)]
	if !inline {
		// Anything outside the safe-inline set (SVG, HTML, JS, PDF, …)
		// goes as a download. SVG in particular contains executable
		// script tags and same-origin renders → XSS primitive for
		// anyone who can guess a file ID.
		ct = "application/octet-stream"
		fname := name + "." + ext
		// Quote the filename in case it carries spaces or unicode.
		w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(fname)+`"`)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.Copy(w, out.Body)
}

// sanitizeFilename strips quote/control characters that would let an
// attacker inject extra headers via a crafted filename in the DB.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == '"' || r == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
