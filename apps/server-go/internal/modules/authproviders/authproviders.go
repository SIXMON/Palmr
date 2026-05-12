// Package authproviders implements admin-managed OIDC providers and the
// public OAuth dance.
//
// Admin endpoints:
//   GET    /auth/providers              list enabled (public)
//   GET    /auth/providers/all          list all (admin)
//   POST   /auth/providers              create
//   PUT    /auth/providers/{id}         update
//   PUT    /auth/providers/order        reorder
//   DELETE /auth/providers/{id}         delete
//
// Public OAuth dance:
//   GET    /auth/providers/{provider}/authorize  start (302 to IdP)
//   GET    /auth/providers/{provider}/callback   IdP redirects here
//
// The callback creates or links a local user, issues the session cookie
// and redirects to the frontend.
package authproviders

import (
	dbtypes "github.com/sixmon/palmr/apps/server-go/internal/db"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/oauth2"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	"github.com/sixmon/palmr/apps/server-go/internal/cookies"
	apperr "github.com/sixmon/palmr/apps/server-go/internal/errors"
)

type Provider struct {
	ID                    string  `db:"id"           json:"id"`
	Name                  string  `db:"name"         json:"name"`
	DisplayName           string  `db:"displayName"  json:"displayName"`
	Type                  string  `db:"type"         json:"type"`
	Icon                  *string `db:"icon"         json:"icon"`
	Enabled               bool    `db:"enabled"      json:"enabled"`
	IssuerURL             *string `db:"issuerUrl"    json:"issuerUrl"`
	ClientID              *string `db:"clientId"     json:"clientId"`
	ClientSecret          *string `db:"clientSecret" json:"-"`
	RedirectURI           *string `db:"redirectUri"  json:"redirectUri"`
	Scope                 *string `db:"scope"        json:"scope"`
	AuthorizationEndpoint *string `db:"authorizationEndpoint" json:"authorizationEndpoint"`
	TokenEndpoint         *string `db:"tokenEndpoint"  json:"tokenEndpoint"`
	UserInfoEndpoint      *string `db:"userInfoEndpoint" json:"userInfoEndpoint"`
	Metadata              *string `db:"metadata"     json:"metadata"`
	AutoRegister          bool    `db:"autoRegister" json:"autoRegister"`
	AdminEmailDomains     *string `db:"adminEmailDomains" json:"adminEmailDomains"`
	SortOrder             int     `db:"sortOrder"    json:"sortOrder"`
	CreatedAt             dbtypes.PrismaTime `db:"createdAt"  json:"createdAt"`
	UpdatedAt             dbtypes.PrismaTime `db:"updatedAt"  json:"updatedAt"`
}

type Handler struct {
	DB         *sqlx.DB
	Signer     *auth.Signer
	SecureSite bool
	CookieTTL  time.Duration

	// state is the in-memory CSRF store for OAuth state values. Plain map,
	// fine for single-instance deployments — swap to Redis if you ever go
	// horizontal.
	state map[string]stateEntry
}

type stateEntry struct {
	Provider     string
	CodeVerifier string
	CreatedAt    time.Time
}

func New(db *sqlx.DB, signer *auth.Signer, secure bool, ttl time.Duration) *Handler {
	return &Handler{DB: db, Signer: signer, SecureSite: secure, CookieTTL: ttl, state: map[string]stateEntry{}}
}

func Register(api huma.API, h *Handler) {
	op := func(m, p, id string) huma.Operation {
		return huma.Operation{Method: m, Path: p, Tags: []string{"Auth Providers"}, OperationID: id}
	}
	huma.Register(api, op(http.MethodGet, "/auth/providers", "listEnabledProviders"), h.ListEnabled)
	huma.Register(api, op(http.MethodGet, "/auth/providers/all", "listAllProviders"), h.ListAll)
	huma.Register(api, op(http.MethodPost, "/auth/providers", "createProvider"), h.Create)
	huma.Register(api, op(http.MethodPut, "/auth/providers/{id}", "updateProvider"), h.Update)
	huma.Register(api, op(http.MethodPut, "/auth/providers/order", "reorderProviders"), h.Reorder)
	huma.Register(api, op(http.MethodDelete, "/auth/providers/{id}", "deleteProvider"), h.Delete)
}

// RegisterPlain attaches the OAuth dance on the chi router directly (huma
// doesn't deal well with 302 responses to outside URLs).
func (h *Handler) RegisterPlain(r chi.Router) {
	r.Get("/auth/providers/{provider}/authorize", h.Authorize)
	r.Get("/auth/providers/{provider}/callback", h.Callback)
}

// -----------------------------------------------------------------------------

type APListOutput struct{ Body struct{ Success bool `json:"success"`; Data []Provider `json:"data"` } }

func (h *Handler) ListEnabled(ctx context.Context, _ *struct{}) (*APListOutput, error) {
	out := &APListOutput{}
	_ = h.DB.SelectContext(ctx, &out.Body.Data,
		`SELECT id, name, displayName, type, icon, enabled, issuerUrl, clientId, redirectUri, scope,
		        authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt
		 FROM auth_providers WHERE enabled = 1 ORDER BY sortOrder ASC`)
	out.Body.Success = true
	return out, nil
}

func (h *Handler) ListAll(ctx context.Context, _ *struct{}) (*APListOutput, error) {
	if _, err := auth.EnsureAuth(ctx); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &APListOutput{}
	_ = h.DB.SelectContext(ctx, &out.Body.Data, `
		SELECT id, name, displayName, type, icon, enabled, issuerUrl, clientId, redirectUri, scope,
		       authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt
		FROM auth_providers ORDER BY sortOrder ASC`)
	out.Body.Success = true
	return out, nil
}

type APCreateInput struct{ Body Provider }
type APSingleOutput struct{ Body struct{ Provider Provider `json:"provider"` } }

func (h *Handler) Create(ctx context.Context, in *APCreateInput) (*APSingleOutput, error) {
	if _, err := auth.EnsureAuth(ctx); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	p := in.Body
	p.ID = uuid.NewString()
	now := time.Now().UTC()
	p.CreatedAt = dbtypes.PrismaTime{Time: now}
	p.UpdatedAt = dbtypes.PrismaTime{Time: now}
	_, err := h.DB.ExecContext(ctx, `
		INSERT INTO auth_providers (id, name, displayName, type, icon, enabled, issuerUrl, clientId, clientSecret,
		redirectUri, scope, authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.DisplayName, p.Type, p.Icon, p.Enabled, p.IssuerURL, p.ClientID, p.ClientSecret,
		p.RedirectURI, p.Scope, p.AuthorizationEndpoint, p.TokenEndpoint, p.UserInfoEndpoint, p.Metadata,
		p.AutoRegister, p.AdminEmailDomains, p.SortOrder, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return nil, apperr.Internal("create provider: " + err.Error())
	}
	out := &APSingleOutput{}
	out.Body.Provider = p
	return out, nil
}

type APUpdateInput struct {
	ID   string `path:"id"`
	Body Provider
}

func (h *Handler) Update(ctx context.Context, in *APUpdateInput) (*APSingleOutput, error) {
	if _, err := auth.EnsureAuth(ctx); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	p := in.Body
	_, err := h.DB.ExecContext(ctx, `
		UPDATE auth_providers SET name=?, displayName=?, type=?, icon=?, enabled=?, issuerUrl=?, clientId=?, clientSecret=?,
		redirectUri=?, scope=?, authorizationEndpoint=?, tokenEndpoint=?, userInfoEndpoint=?, metadata=?,
		autoRegister=?, adminEmailDomains=?, sortOrder=?, updatedAt=CURRENT_TIMESTAMP WHERE id=?`,
		p.Name, p.DisplayName, p.Type, p.Icon, p.Enabled, p.IssuerURL, p.ClientID, p.ClientSecret,
		p.RedirectURI, p.Scope, p.AuthorizationEndpoint, p.TokenEndpoint, p.UserInfoEndpoint, p.Metadata,
		p.AutoRegister, p.AdminEmailDomains, p.SortOrder, in.ID)
	if err != nil {
		return nil, apperr.Internal("update provider")
	}
	out := &APSingleOutput{}
	out.Body.Provider = p
	out.Body.Provider.ID = in.ID
	return out, nil
}

type APReorderEntry struct {
	ID    string `json:"id"`
	Order int    `json:"order"`
}
type APReorderInput struct {
	Body struct {
		Order []APReorderEntry `json:"order"`
	}
}
type APMsgOutput struct{ Body struct{ Message string `json:"message"` } }

func (h *Handler) Reorder(ctx context.Context, in *APReorderInput) (*APMsgOutput, error) {
	if _, err := auth.EnsureAuth(ctx); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin")
	}
	defer tx.Rollback()
	for _, p := range in.Body.Order {
		_, _ = tx.ExecContext(ctx, `UPDATE auth_providers SET sortOrder=? WHERE id=?`, p.Order, p.ID)
	}
	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit")
	}
	out := &APMsgOutput{}
	out.Body.Message = "reordered"
	return out, nil
}

type APDeleteInput struct{ ID string `path:"id"` }

func (h *Handler) Delete(ctx context.Context, in *APDeleteInput) (*APMsgOutput, error) {
	if _, err := auth.EnsureAuth(ctx); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete provider")
	}
	out := &APMsgOutput{}
	out.Body.Message = "deleted"
	return out, nil
}

// -----------------------------------------------------------------------------
// OAuth dance
// -----------------------------------------------------------------------------

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")
	p, err := h.loadByName(r.Context(), name)
	if err != nil || !p.Enabled {
		http.Error(w, "provider not found or disabled", http.StatusNotFound)
		return
	}
	verifier, challenge := pkcePair()
	stateID := genState()
	h.state[stateID] = stateEntry{Provider: name, CodeVerifier: verifier, CreatedAt: time.Now()}
	go h.gcState()

	conf, ctx := h.oauth2Config(r.Context(), p)
	_ = ctx
	url := conf.AuthCodeURL(stateID,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	stateID := r.URL.Query().Get("state")

	st, ok := h.state[stateID]
	if !ok || st.Provider != name {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	delete(h.state, stateID)

	p, err := h.loadByName(r.Context(), name)
	if err != nil || !p.Enabled {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}

	conf, ctx := h.oauth2Config(r.Context(), p)
	tok, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", st.CodeVerifier))
	if err != nil {
		http.Error(w, "token exchange: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Pull userinfo. If the provider has an OIDC issuer we use go-oidc;
	// otherwise we hit userInfoEndpoint directly.
	email, sub, err := h.fetchIdentity(ctx, p, tok)
	if err != nil {
		http.Error(w, "userinfo: "+err.Error(), http.StatusBadGateway)
		return
	}
	if email == "" || sub == "" {
		http.Error(w, "missing claims", http.StatusBadGateway)
		return
	}

	// Link or create user.
	userID, isAdmin, err := h.linkOrCreate(r.Context(), p, email, sub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jwtStr, err := h.Signer.Sign(userID, isAdmin)
	if err != nil {
		http.Error(w, "issue token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cookies.Set(w, jwtStr, cookies.Options{Secure: h.SecureSite, MaxAge: h.CookieTTL})

	// Redirect to the frontend's /auth/callback page so it can refresh.
	front := h.frontendURL(r)
	http.Redirect(w, r, front+"/auth/callback", http.StatusFound)
}

func (h *Handler) oauth2Config(ctx context.Context, p Provider) (*oauth2.Config, context.Context) {
	scopes := []string{"openid", "profile", "email"}
	if p.Scope != nil && *p.Scope != "" {
		scopes = strings.Split(*p.Scope, " ")
	}
	conf := &oauth2.Config{
		ClientID:     deref(p.ClientID),
		ClientSecret: deref(p.ClientSecret),
		RedirectURL:  deref(p.RedirectURI),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  deref(p.AuthorizationEndpoint),
			TokenURL: deref(p.TokenEndpoint),
		},
	}
	// If we have an issuer URL we can let go-oidc discover endpoints
	// (this overrides the manual auth/token URLs).
	if p.IssuerURL != nil && *p.IssuerURL != "" {
		if prov, err := oidc.NewProvider(ctx, *p.IssuerURL); err == nil {
			conf.Endpoint = prov.Endpoint()
		}
	}
	return conf, ctx
}

func (h *Handler) fetchIdentity(ctx context.Context, p Provider, tok *oauth2.Token) (email, sub string, err error) {
	if p.IssuerURL != nil && *p.IssuerURL != "" {
		prov, err := oidc.NewProvider(ctx, *p.IssuerURL)
		if err != nil {
			return "", "", err
		}
		rawID, ok := tok.Extra("id_token").(string)
		if ok && rawID != "" {
			verifier := prov.Verifier(&oidc.Config{ClientID: deref(p.ClientID)})
			idTok, err := verifier.Verify(ctx, rawID)
			if err == nil {
				var c struct {
					Email   string `json:"email"`
					Subject string `json:"sub"`
				}
				if err := idTok.Claims(&c); err == nil && c.Email != "" {
					return strings.ToLower(c.Email), c.Subject, nil
				}
			}
		}
		// Fall through to userinfo
		ui, err := prov.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return "", "", err
		}
		var c struct {
			Email   string `json:"email"`
			Subject string `json:"sub"`
		}
		if err := ui.Claims(&c); err != nil {
			return "", "", err
		}
		return strings.ToLower(c.Email), c.Subject, nil
	}
	// Plain OAuth2 (no OIDC) — hit userInfoEndpoint manually.
	return "", "", apperr.BadRequest("non-OIDC providers not yet supported")
}

func (h *Handler) linkOrCreate(ctx context.Context, p Provider, email, sub string) (string, bool, error) {
	// 1) Existing link?
	var userID string
	err := h.DB.GetContext(ctx, &userID,
		`SELECT userId FROM user_auth_providers WHERE providerId = ? AND externalId = ?`, p.ID, sub)
	if err == nil {
		var isAdmin bool
		_ = h.DB.GetContext(ctx, &isAdmin, `SELECT isAdmin FROM users WHERE id = ?`, userID)
		return userID, isAdmin, nil
	}
	// 2) User exists by email?
	err = h.DB.GetContext(ctx, &userID, `SELECT id FROM users WHERE email = ?`, email)
	if err == nil {
		_, _ = h.DB.ExecContext(ctx,
			`INSERT INTO user_auth_providers (id, userId, providerId, externalId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
			uuid.NewString(), userID, p.ID, sub, time.Now(), time.Now())
		var isAdmin bool
		_ = h.DB.GetContext(ctx, &isAdmin, `SELECT isAdmin FROM users WHERE id = ?`, userID)
		return userID, isAdmin, nil
	}
	// 3) Auto-register?
	if !p.AutoRegister {
		return "", false, apperr.Forbidden("auto-register disabled for this provider")
	}
	uid := uuid.NewString()
	isAdmin := false
	if p.AdminEmailDomains != nil {
		for _, d := range strings.Split(*p.AdminEmailDomains, ",") {
			if strings.EqualFold(strings.TrimSpace(d), strings.SplitN(email, "@", 2)[1]) {
				isAdmin = true
				break
			}
		}
	}
	username := strings.SplitN(email, "@", 2)[0]
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO users (id, firstName, lastName, username, email, isAdmin, isActive, createdAt, updatedAt, twoFactorEnabled, twoFactorVerified)
		VALUES (?, ?, '', ?, ?, ?, 1, ?, ?, 0, 0)`,
		uid, username, username, email, isAdmin, now, now)
	if err != nil {
		return "", false, apperr.Internal("auto-register: " + err.Error())
	}
	_, _ = h.DB.ExecContext(ctx,
		`INSERT INTO user_auth_providers (id, userId, providerId, externalId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), uid, p.ID, sub, now, now)
	return uid, isAdmin, nil
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func (h *Handler) loadByName(ctx context.Context, name string) (Provider, error) {
	var p Provider
	err := h.DB.GetContext(ctx, &p, `
		SELECT id, name, displayName, type, icon, enabled, issuerUrl, clientId, clientSecret, redirectUri, scope,
		       authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt
		FROM auth_providers WHERE name = ?`, name)
	return p, err
}

func (h *Handler) frontendURL(r *http.Request) string {
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = strings.SplitN(v, ",", 2)[0]
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = strings.SplitN(v, ",", 2)[0]
	}
	return scheme + "://" + strings.TrimSpace(host)
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (h *Handler) gcState() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, v := range h.state {
		if v.CreatedAt.Before(cutoff) {
			delete(h.state, k)
		}
	}
}

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func genState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
