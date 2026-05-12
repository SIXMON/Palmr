// Package uploads handles the few multipart/form-data endpoints (avatar
// and app logo). They sit outside huma's typed-handler world because
// huma 2.x doesn't have a stable ergonomic story for multipart yet.
//
// Routes:
//   POST   /users/avatar             — own avatar (auth)
//   DELETE /users/avatar             — clear own avatar (auth)
//   PATCH  /users/{id}/image         — admin sets a user's avatar
//   POST   /app/logo                 — app logo (admin)
//   DELETE /app/logo                 — clear app logo (admin)
//
// Avatars are stored as bytes inside the SQLite `users.image` column —
// matches what the legacy backend does (data URI) so the frontend can
// render them without a separate fetch.
package uploads

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
	"github.com/sixmon/palmr/apps/server-go/internal/imageresize"
)

const (
	maxAvatarBytes = 5 << 20 // 5 MB
	maxLogoBytes   = 5 << 20 // 5 MB
	avatarPx       = 256
	logoPx         = 512
)

type Handler struct {
	DB         *sqlx.DB
	SecureSite bool
}

// Register attaches the multipart routes to chi. The package is wired
// from main.go right after the huma API setup.
func (h *Handler) Register(r chi.Router) {
	r.Post("/users/avatar", h.uploadOwnAvatar)
	r.Delete("/users/avatar", h.removeOwnAvatar)
	r.Patch("/users/{id}/image", h.adminSetUserAvatar)
	r.Post("/app/logo", h.uploadAppLogo)
	r.Delete("/app/logo", h.removeAppLogo)
}

// -----------------------------------------------------------------------------
// Avatar
// -----------------------------------------------------------------------------

func (h *Handler) uploadOwnAvatar(w http.ResponseWriter, r *http.Request) {
	uc, ok := auth.FromContext(r.Context())
	if !ok {
		apperr.WriteJSON(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	dataURI, err := h.readAndProcess(r, maxAvatarBytes, avatarPx, imageresize.JPEG)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET image = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		dataURI, uc.UserID); err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "update user")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"avatar updated"}`))
}

func (h *Handler) removeOwnAvatar(w http.ResponseWriter, r *http.Request) {
	uc, ok := auth.FromContext(r.Context())
	if !ok {
		apperr.WriteJSON(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET image = NULL, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		uc.UserID); err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "update user")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"avatar removed"}`))
}

func (h *Handler) adminSetUserAvatar(w http.ResponseWriter, r *http.Request) {
	uc, ok := auth.FromContext(r.Context())
	if !ok || !uc.IsAdmin {
		apperr.WriteJSON(w, http.StatusForbidden, "admin only")
		return
	}
	id := chi.URLParam(r, "id")
	dataURI, err := h.readAndProcess(r, maxAvatarBytes, avatarPx, imageresize.JPEG)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET image = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`,
		dataURI, id); err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "update user")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"avatar updated"}`))
}

// -----------------------------------------------------------------------------
// App logo
// -----------------------------------------------------------------------------

func (h *Handler) uploadAppLogo(w http.ResponseWriter, r *http.Request) {
	uc, ok := auth.FromContext(r.Context())
	if !ok || !uc.IsAdmin {
		apperr.WriteJSON(w, http.StatusForbidden, "admin only")
		return
	}
	dataURI, err := h.readAndProcess(r, maxLogoBytes, logoPx, imageresize.PNG)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE app_configs SET value = ?, updatedAt = CURRENT_TIMESTAMP WHERE key = 'appLogo'`,
		dataURI); err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "update logo")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"logo updated"}`))
}

func (h *Handler) removeAppLogo(w http.ResponseWriter, r *http.Request) {
	uc, ok := auth.FromContext(r.Context())
	if !ok || !uc.IsAdmin {
		apperr.WriteJSON(w, http.StatusForbidden, "admin only")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE app_configs SET value = '', updatedAt = CURRENT_TIMESTAMP WHERE key = 'appLogo'`); err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "update logo")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"logo removed"}`))
}

// -----------------------------------------------------------------------------
// Shared multipart reader. Accepts either:
//   - a multipart/form-data body with one file field (any name) — what
//     the web UI sends
//   - a raw image body when Content-Type starts with image/* — useful
//     for CLI clients
// Returns a data URI string ready to stash in the database column.
// -----------------------------------------------------------------------------

func (h *Handler) readAndProcess(r *http.Request, maxBytes int64, dim int, enc imageresize.Encoding) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)

	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "multipart/form-data"):
		if err := r.ParseMultipartForm(maxBytes); err != nil {
			return "", errors.New("parse multipart: " + err.Error())
		}
		var src io.Reader
		for _, files := range r.MultipartForm.File {
			if len(files) > 0 {
				f, err := files[0].Open()
				if err != nil {
					return "", err
				}
				defer f.Close()
				src = f
				break
			}
		}
		if src == nil {
			return "", errors.New("no file in form")
		}
		out, err := imageresize.Resize(src, dim, enc)
		if err != nil {
			return "", err
		}
		return "data:" + out.ContentType + ";base64," + base64.StdEncoding.EncodeToString(out.Data), nil

	case strings.HasPrefix(ct, "image/"):
		out, err := imageresize.Resize(r.Body, dim, enc)
		if err != nil {
			return "", err
		}
		return "data:" + out.ContentType + ";base64," + base64.StdEncoding.EncodeToString(out.Data), nil

	default:
		return "", errors.New("expected multipart/form-data or image/*")
	}
}
