// Package invite implements admin-only invite tokens.
//
//   POST   /invite-tokens          create
//   GET    /invite-tokens          list (admin)
//   GET    /invite-tokens/{token}  validate (public)
//   POST   /register-with-invite   register through invite (public)
package invite

import (
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
)

type Handler struct {
	DB         *sqlx.DB
	BcryptCost int
}

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"Invite"}, OperationID: id}
	}
	huma.Register(api, op(http.MethodPost, "/invite-tokens", "createInviteToken"), h.Create)
	huma.Register(api, op(http.MethodGet, "/invite-tokens", "listInviteTokens"), h.List)
	huma.Register(api, op(http.MethodGet, "/invite-tokens/{token}", "getInviteToken"), h.Get)
	huma.Register(api, op(http.MethodPost, "/register-with-invite", "registerWithInvite"), h.RegisterWithInvite)
}

type Token struct {
	Token     string     `db:"token"     json:"token"`
	ExpiresAt dbtypes.PrismaTime  `db:"expiresAt" json:"expiresAt"`
	UsedAt    *dbtypes.PrismaTime `db:"usedAt"    json:"usedAt"`
	CreatedBy string     `db:"createdBy" json:"createdBy"`
}

type InviteCreateInput struct {
	Body struct {
		ExpiresInHours int `json:"expiresInHours,omitempty"`
	}
}

// InviteCreateOutput is the flat `{token, expiresAt}` shape the frontend
// expects (`GenerateInviteTokenResponse` in apps/web/.../invite/types.ts).
// The legacy code returned `{inviteToken: {…}}` and the modal that builds the
// invite URL did `${origin}/register-with-invite/${response.token}` — with the
// wrapper, that URL ended with `/undefined`.
type InviteCreateOutput struct {
	Body struct {
		Token     string             `json:"token"`
		ExpiresAt dbtypes.PrismaTime `json:"expiresAt"`
	}
}
type InviteListOutput struct{ Body struct{ Tokens []Token `json:"inviteTokens"` } }
type InviteGetInput struct{ Token string `path:"token"` }

// InviteGetOutput matches `ValidateInviteTokenResponse` — explicit `used` and
// `expired` booleans so the register page (`apps/web/.../register-with-invite/
// [token]/page.tsx`) can branch to the right error copy. A single `reason`
// string left every error falling through to the generic "invalid" branch.
type InviteGetOutput struct {
	Body struct {
		Valid   bool `json:"valid"`
		Used    bool `json:"used,omitempty"`
		Expired bool `json:"expired,omitempty"`
	}
}

func (h *Handler) Create(ctx context.Context, in *InviteCreateInput) (*InviteCreateOutput, error) {
	uc, err := auth.EnsureAdmin(ctx, h.DB)
	if err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	hours := in.Body.ExpiresInHours
	if hours <= 0 {
		hours = 72
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(hours) * time.Hour)
	_, err = h.DB.ExecContext(ctx,
		`INSERT INTO invite_tokens (id, token, expiresAt, createdBy, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), tok, expiresAt, uc.UserID, now, now)
	if err != nil {
		return nil, apperr.Internal("create invite: " + err.Error())
	}
	out := &InviteCreateOutput{}
	out.Body.Token = tok
	out.Body.ExpiresAt = dbtypes.PrismaTime{Time: expiresAt}
	return out, nil
}

func (h *Handler) List(ctx context.Context, _ *struct{}) (*InviteListOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &InviteListOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Tokens = []Token{}
	_ = h.DB.SelectContext(ctx, &out.Body.Tokens, `SELECT token, expiresAt, usedAt, createdBy FROM invite_tokens ORDER BY createdAt DESC`)
	return out, nil
}

func (h *Handler) Get(ctx context.Context, in *InviteGetInput) (*InviteGetOutput, error) {
	out := &InviteGetOutput{}
	var t Token
	if err := h.DB.GetContext(ctx, &t, `SELECT token, expiresAt, usedAt, createdBy FROM invite_tokens WHERE token = ?`, in.Token); err != nil {
		// Not found — neither used nor expired; just invalid.
		out.Body.Valid = false
		return out, nil
	}
	if t.UsedAt != nil {
		out.Body.Valid = false
		out.Body.Used = true
		return out, nil
	}
	if time.Now().After(t.ExpiresAt.Time) {
		out.Body.Valid = false
		out.Body.Expired = true
		return out, nil
	}
	out.Body.Valid = true
	return out, nil
}

type InviteRegisterInput struct {
	Body struct {
		Token     string `json:"token" required:"true"`
		FirstName string `json:"firstName" required:"true"`
		LastName  string `json:"lastName" required:"true"`
		Username  string `json:"username" required:"true"`
		Email     string `json:"email" required:"true" format:"email"`
		Password  string `json:"password" required:"true" minLength:"8"`
	}
}
type InviteRegisterOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

func (h *Handler) RegisterWithInvite(ctx context.Context, in *InviteRegisterInput) (*InviteRegisterOutput, error) {
	var t Token
	if err := h.DB.GetContext(ctx, &t, `SELECT token, expiresAt, usedAt, createdBy FROM invite_tokens WHERE token = ?`, in.Body.Token); err != nil {
		return nil, apperr.NotFound("invite not found")
	}
	if t.UsedAt != nil {
		return nil, apperr.Conflict("invite already used")
	}
	if time.Now().After(t.ExpiresAt.Time) {
		return nil, apperr.Gone("invite expired")
	}
	hash, err := auth.HashPassword(in.Body.Password, h.BcryptCost)
	if err != nil {
		return nil, apperr.BadRequest(err.Error())
	}
	email := strings.ToLower(in.Body.Email)
	now := time.Now().UTC()
	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin")
	}
	defer tx.Rollback()
	uid := uuid.NewString()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (id, firstName, lastName, username, email, password, isAdmin, isActive, createdAt, updatedAt, twoFactorEnabled, twoFactorVerified)
		VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, 0, 0)`,
		uid, in.Body.FirstName, in.Body.LastName, in.Body.Username, email, hash, now, now)
	if err != nil {
		return nil, apperr.Conflict("email or username already exists")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invite_tokens SET usedAt = ?, updatedAt = ? WHERE token = ?`, now, now, t.Token); err != nil {
		return nil, apperr.Internal("mark token used")
	}
	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit")
	}
	out := &InviteRegisterOutput{}
	out.Body.Message = "User created"
	return out, nil
}
