// Package user implements user CRUD + the bootstrap-admin register flow.
//
// POST   /auth/register        — register a new user (admin only, bootstrap-bypass when DB empty)
// GET    /users                — list users (admin only)
// GET    /users/:id            — fetch one (admin only)
// PUT    /users                — update own profile (auth)
// DELETE /users/:id            — delete user (admin only)
// PATCH  /users/:id/activate   — reactivate (admin only)
// PATCH  /users/:id/deactivate — deactivate (admin only)
//
// Avatar upload (POST/DELETE /users/avatar, PATCH /users/:id/image) is
// skipped in this MVP — the page works without it, the legacy backend's
// implementation can be ported later (it just streams to /data and writes
// the URL into users.image).
package user

import (
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	humaauth "github.com/sixmon/palmr/apps/server/internal/auth"
	"github.com/sixmon/palmr/apps/server/internal/cookies"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

type User struct {
	ID        string    `db:"id"        json:"id"`
	FirstName string    `db:"firstName" json:"firstName"`
	LastName  string    `db:"lastName"  json:"lastName"`
	Username  string    `db:"username"  json:"username"`
	Email     string    `db:"email"     json:"email"`
	Image     *string   `db:"image"     json:"image"`
	IsAdmin   bool      `db:"isAdmin"   json:"isAdmin"`
	IsActive  bool      `db:"isActive"  json:"isActive"`
	CreatedAt dbtypes.PrismaTime `db:"createdAt" json:"createdAt"`
	UpdatedAt dbtypes.PrismaTime `db:"updatedAt" json:"updatedAt"`
}

type Handler struct {
	DB         *sqlx.DB
	Signer     *humaauth.Signer
	BcryptCost int
	SecureSite bool
	CookieTTL  time.Duration
}

// -----------------------------------------------------------------------------
// Public registration (handled here because it shares the User type).
// -----------------------------------------------------------------------------

func RegisterPublic(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodPost, Path: "/auth/register",
		Tags: []string{"User"}, OperationID: "registerUser",
		DefaultStatus: http.StatusCreated,
	}, h.Register)
}

func RegisterAdmin(api huma.API, h *Handler) {
	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/users",
		Tags: []string{"User"}, OperationID: "listUsers",
	}, h.List)

	huma.Register(api, huma.Operation{
		Method: http.MethodGet, Path: "/users/{id}",
		Tags: []string{"User"}, OperationID: "getUserById",
	}, h.GetByID)

	huma.Register(api, huma.Operation{
		Method: http.MethodPut, Path: "/users",
		Tags: []string{"User"}, OperationID: "updateUser",
	}, h.UpdateSelf)

	huma.Register(api, huma.Operation{
		Method: http.MethodDelete, Path: "/users/{id}",
		Tags: []string{"User"}, OperationID: "deleteUser",
	}, h.Delete)

	huma.Register(api, huma.Operation{
		Method: http.MethodPatch, Path: "/users/{id}/activate",
		Tags: []string{"User"}, OperationID: "activateUser",
	}, h.Activate)

	huma.Register(api, huma.Operation{
		Method: http.MethodPatch, Path: "/users/{id}/deactivate",
		Tags: []string{"User"}, OperationID: "deactivateUser",
	}, h.Deactivate)
}

// -----------------------------------------------------------------------------
// POST /auth/register
//
// Bootstrap rule (matches the legacy backend): when no users exist yet,
// the very first registration becomes admin and gets a fresh session
// cookie issued in the same response, so the UI can immediately call
// admin endpoints (firstUserAccess=false, etc).
// -----------------------------------------------------------------------------

type UserRegisterInput struct {
	Body struct {
		FirstName string  `json:"firstName" required:"true" minLength:"1"`
		LastName  string  `json:"lastName"  required:"true" minLength:"1"`
		Username  string  `json:"username"  required:"true" minLength:"3"`
		Email     string  `json:"email"     required:"true" format:"email"`
		Password  string  `json:"password"  required:"true" minLength:"8" maxLength:"72"`
		Image     *string `json:"image,omitempty"`
	}
}

type UserRegisterOutput struct {
	Body struct {
		User    User   `json:"user"`
		Message string `json:"message"`
	}
	SetCookie http.Cookie `header:"Set-Cookie"`
}

func (h *Handler) Register(ctx context.Context, in *UserRegisterInput) (*UserRegisterOutput, error) {
	email := strings.ToLower(strings.TrimSpace(in.Body.Email))
	username := strings.TrimSpace(in.Body.Username)

	var count int
	_ = h.DB.GetContext(ctx, &count, `SELECT COUNT(*) FROM users WHERE email = ? OR username = ?`, email, username)
	if count > 0 {
		return nil, apperr.Conflict("user with this email or username already exists")
	}

	hash, err := humaauth.HashPassword(in.Body.Password, h.BcryptCost)
	if err != nil {
		return nil, apperr.BadRequest(err.Error())
	}

	var usersCount int
	if err := h.DB.GetContext(ctx, &usersCount, `SELECT COUNT(*) FROM users`); err != nil {
		return nil, apperr.Internal("count users")
	}
	isAdmin := usersCount == 0

	id := uuid.NewString()
	now := time.Now().UTC()

	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO users (id, firstName, lastName, username, email, password, image, isAdmin, isActive, createdAt, updatedAt, twoFactorEnabled, twoFactorVerified)
		VALUES (?,  ?,         ?,        ?,        ?,     ?,        ?,     ?,       ?,        ?,         ?,         0,                0)`,
		id, in.Body.FirstName, in.Body.LastName, username, email, hash, in.Body.Image, isAdmin, true, now, now)
	if err != nil {
		return nil, apperr.Internal("create user: " + err.Error())
	}

	u, err := h.loadUser(ctx, id)
	if err != nil {
		return nil, apperr.Internal("reload user")
	}

	out := &UserRegisterOutput{}
	out.Body.User = u
	out.Body.Message = "User created successfully"

	// Bootstrap admin auto-login (parity with the legacy f539569 fix).
	if isAdmin {
		token, err := h.Signer.Sign(u.ID, true)
		if err != nil {
			return nil, apperr.Internal("issue token")
		}
		out.SetCookie = http.Cookie{
			Name:     cookies.Name,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   h.SecureSite,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(h.CookieTTL.Seconds()),
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /users
// -----------------------------------------------------------------------------

// UserListOutput returns a bare JSON array — the frontend types this as
// `ListUsersResult = AxiosResponse<User[]>` and calls `setUsers(response.data)`
// directly (apps/web/.../users-management/hooks/use-user-management.ts). Wrapping
// in `{users:[...]}` breaks `.map`/`.filter`/`.length` on the users page.
type UserListOutput struct {
	Body []User
}

func (h *Handler) List(ctx context.Context, _ *struct{}) (*UserListOutput, error) {
	if _, err := humaauth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	out := &UserListOutput{Body: []User{}}
	if err := h.DB.SelectContext(ctx, &out.Body,
		`SELECT id, firstName, lastName, username, email, image, isAdmin, isActive, createdAt, updatedAt
		 FROM users ORDER BY createdAt DESC`); err != nil {
		return nil, apperr.Internal("list users")
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// GET /users/:id
// -----------------------------------------------------------------------------

type GetByIDInput struct{ ID string `path:"id"` }

// GetByIDOutput returns the user as a bare JSON object — matching
// `GetUserById200 = User`, `ActivateUser200 = User`, `DeactivateUser200 =
// User` on the frontend. Wrapping it in `{user: …}` would mean those
// admin pages can't `setUser(response.data)` directly.
type GetByIDOutput struct {
	Body User
}

func (h *Handler) GetByID(ctx context.Context, in *GetByIDInput) (*GetByIDOutput, error) {
	if _, err := humaauth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	u, err := h.loadUser(ctx, in.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperr.NotFound("user not found")
		}
		return nil, apperr.Internal("load user")
	}
	return &GetByIDOutput{Body: u}, nil
}

// -----------------------------------------------------------------------------
// PUT /users — update own profile.
// -----------------------------------------------------------------------------

// UserUpdateInput matches the frontend's `UpdateUserBody` (apps/web/.../
// users/types.ts). It's a dual-purpose endpoint:
//
//   - Self-edit: the body's `id` is empty or matches the caller's own
//     user ID. Profile fields can be changed; `isAdmin` is silently
//     ignored (a non-admin must not be able to flip their own bit).
//   - Admin-edit: the body's `id` targets another user. We require the
//     caller to be admin; all fields (including `isAdmin`) are honoured.
//
// The legacy Node backend used this same shape — both the profile page
// and the admin users-management page POST through it.
type UserUpdateInput struct {
	Body struct {
		ID        string  `json:"id,omitempty"`
		FirstName *string `json:"firstName,omitempty"`
		LastName  *string `json:"lastName,omitempty"`
		Username  *string `json:"username,omitempty"`
		Email     *string `json:"email,omitempty" format:"email"`
		Image     *string `json:"image,omitempty"`
		Password  *string `json:"password,omitempty" minLength:"8" maxLength:"72"`
		IsAdmin   *bool   `json:"isAdmin,omitempty"`
	}
}

// UserUpdateOutput returns the refreshed user as a bare JSON object —
// the frontend types this as `UpdateUser200 = User` (no `{user:…}`
// wrapper).
type UserUpdateOutput struct {
	Body User
}

func (h *Handler) UpdateSelf(ctx context.Context, in *UserUpdateInput) (*UserUpdateOutput, error) {
	uc, ok := humaauth.FromContext(ctx)
	if !ok {
		return nil, apperr.Unauthorized("missing user context")
	}

	targetID := in.Body.ID
	if targetID == "" {
		targetID = uc.UserID
	}
	isSelf := targetID == uc.UserID

	// Editing another user requires admin. Non-admins also can't flip
	// their own isAdmin bit (silently dropped further down).
	if !isSelf {
		if _, err := humaauth.EnsureAdmin(ctx, h.DB); err != nil {
			return nil, apperr.Forbidden(err.Error())
		}
	}

	fields := []string{}
	args := []any{}
	if in.Body.FirstName != nil {
		fields = append(fields, "firstName = ?")
		args = append(args, *in.Body.FirstName)
	}
	if in.Body.LastName != nil {
		fields = append(fields, "lastName = ?")
		args = append(args, *in.Body.LastName)
	}
	if in.Body.Username != nil {
		fields = append(fields, "username = ?")
		args = append(args, *in.Body.Username)
	}
	if in.Body.Email != nil {
		fields = append(fields, "email = ?")
		args = append(args, strings.ToLower(*in.Body.Email))
	}
	if in.Body.Image != nil {
		fields = append(fields, "image = ?")
		args = append(args, *in.Body.Image)
	}
	if in.Body.Password != nil {
		hash, err := humaauth.HashPassword(*in.Body.Password, h.BcryptCost)
		if err != nil {
			return nil, apperr.BadRequest(err.Error())
		}
		fields = append(fields, "password = ?")
		args = append(args, hash)
	}
	// isAdmin is admin-only — silently ignored on self-edit so a
	// compromised XSS in the profile page can't grant itself admin.
	if in.Body.IsAdmin != nil && !isSelf {
		fields = append(fields, "isAdmin = ?")
		args = append(args, *in.Body.IsAdmin)
	}
	if len(fields) == 0 {
		return nil, apperr.BadRequest("nothing to update")
	}
	fields = append(fields, "updatedAt = CURRENT_TIMESTAMP")
	args = append(args, targetID)
	q := "UPDATE users SET " + strings.Join(fields, ", ") + " WHERE id = ?"
	if _, err := h.DB.ExecContext(ctx, q, args...); err != nil {
		return nil, apperr.Internal("update user")
	}
	u, err := h.loadUser(ctx, targetID)
	if err != nil {
		return nil, apperr.NotFound("user not found")
	}
	return &UserUpdateOutput{Body: u}, nil
}

// -----------------------------------------------------------------------------
// DELETE /users/:id
// -----------------------------------------------------------------------------

type UserDeleteOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (h *Handler) Delete(ctx context.Context, in *GetByIDInput) (*UserDeleteOutput, error) {
	if _, err := humaauth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	res, err := h.DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, in.ID)
	if err != nil {
		return nil, apperr.Internal("delete user")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, apperr.NotFound("user not found")
	}
	out := &UserDeleteOutput{}
	out.Body.Message = "User deleted"
	return out, nil
}

// -----------------------------------------------------------------------------
// PATCH /users/:id/activate, /deactivate
// -----------------------------------------------------------------------------

func (h *Handler) Activate(ctx context.Context, in *GetByIDInput) (*GetByIDOutput, error) {
	return h.setActive(ctx, in.ID, true)
}
func (h *Handler) Deactivate(ctx context.Context, in *GetByIDInput) (*GetByIDOutput, error) {
	return h.setActive(ctx, in.ID, false)
}

func (h *Handler) setActive(ctx context.Context, id string, active bool) (*GetByIDOutput, error) {
	if _, err := humaauth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Forbidden(err.Error())
	}
	if _, err := h.DB.ExecContext(ctx, `UPDATE users SET isActive = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?`, active, id); err != nil {
		return nil, apperr.Internal("update user")
	}
	u, err := h.loadUser(ctx, id)
	if err != nil {
		return nil, apperr.NotFound("user not found")
	}
	return &GetByIDOutput{Body: u}, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func (h *Handler) loadUser(ctx context.Context, id string) (User, error) {
	var u User
	err := h.DB.GetContext(ctx, &u,
		`SELECT id, firstName, lastName, username, email, image, isAdmin, isActive, createdAt, updatedAt
		 FROM users WHERE id = ?`, id)
	return u, err
}
