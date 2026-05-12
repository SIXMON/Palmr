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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	dbtypes "github.com/sixmon/palmr/apps/server-go/internal/db"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
	"github.com/sixmon/palmr/apps/server-go/internal/imageresize"
)

// userRow is the JSON shape the frontend's profile page (`use-profile.ts`)
// drops into both `userData` and `user` state after an avatar upload/remove.
// We can't reach into the `user` package without a cycle, so duplicate the
// minimal shape here.
type userRow struct {
	ID        string             `db:"id"        json:"id"`
	FirstName string             `db:"firstName" json:"firstName"`
	LastName  string             `db:"lastName"  json:"lastName"`
	Username  string             `db:"username"  json:"username"`
	Email     string             `db:"email"     json:"email"`
	Image     *string            `db:"image"     json:"image"`
	IsAdmin   bool               `db:"isAdmin"   json:"isAdmin"`
	IsActive  bool               `db:"isActive"  json:"isActive"`
	CreatedAt dbtypes.PrismaTime `db:"createdAt" json:"createdAt"`
	UpdatedAt dbtypes.PrismaTime `db:"updatedAt" json:"updatedAt"`
}

func (h *Handler) loadUserRow(r *http.Request, id string) (*userRow, error) {
	var u userRow
	err := h.DB.GetContext(r.Context(), &u,
		`SELECT id, firstName, lastName, username, email, image, isAdmin, isActive, createdAt, updatedAt
		 FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

const (
	// Upload size caps apply to the *raw* multipart request body. Both
	// avatars and logos get resized to a small dimension server-side, but
	// the client still uploads the source file. Phone JPEGs routinely
	// land in the 8–15 MB range, so a 5 MB cap (the previous value) was
	// rejecting most real photos with `http: request body too large`.
	maxAvatarBytes = 20 << 20 // 20 MB
	maxLogoBytes   = 10 << 20 // 10 MB
	// multipartMemoryBytes is how much of the parsed form ParseMultipartForm
	// keeps in RAM before spilling to a temp file. It can be much smaller
	// than the body cap — the file field gets streamed through, not held.
	multipartMemoryBytes = 4 << 20 // 4 MB
	avatarPx             = 256
	logoPx               = 512
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

// uploadOwnAvatar returns the full refreshed user row. The profile page
// (`apps/web/.../profile/hooks/use-profile.ts`) calls
// `setUserData(response.data); setUser(response.data)` — handing it a
// `{message: "…"}` object wipes the displayed name/email/etc until refresh.
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
	u, err := h.loadUserRow(r, uc.UserID)
	if err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "reload user")
		return
	}
	writeJSON(w, http.StatusOK, u)
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
	u, err := h.loadUserRow(r, uc.UserID)
	if err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "reload user")
		return
	}
	writeJSON(w, http.StatusOK, u)
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
	u, err := h.loadUserRow(r, id)
	if err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "reload user")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// -----------------------------------------------------------------------------
// App logo
// -----------------------------------------------------------------------------

// uploadAppLogo returns `{logo: <data-uri>}` because the settings UI reads
// `response.data.logo` to swap the preview (`apps/web/.../settings/components/
// logo-input.tsx`). Returning a `{message: …}` envelope made the preview blank
// out after upload even though the DB value was set.
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
	writeJSON(w, http.StatusOK, map[string]string{"logo": dataURI})
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
		// ParseMultipartForm's argument is the in-memory buffer size, not
		// the body cap — the cap is already enforced by MaxBytesReader
		// above. Using a small RAM budget keeps multi-MB photos from
		// being held in process memory unnecessarily.
		if err := r.ParseMultipartForm(multipartMemoryBytes); err != nil {
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
