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
	dbtypes "github.com/sixmon/palmr/apps/server/internal/db"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/oauth2"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	"github.com/sixmon/palmr/apps/server/internal/cookies"
	apperr "github.com/sixmon/palmr/apps/server/internal/errors"
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

	// state is the in-memory CSRF store for OAuth state values, guarded
	// by stateMu. Plain map, fine for single-instance deployments — swap
	// to Redis if you ever go horizontal. Without the mutex two
	// concurrent Authorize calls (or one Authorize + a Callback for an
	// older state) race the map and can crash the process under the
	// Go runtime's concurrent-map-access detector.
	stateMu sync.RWMutex
	state   map[string]stateEntry
}

type stateEntry struct {
	Provider     string
	CodeVerifier string
	CreatedAt    time.Time
}

func New(db *sqlx.DB, signer *auth.Signer, secure bool, ttl time.Duration) *Handler {
	return &Handler{DB: db, Signer: signer, SecureSite: secure, CookieTTL: ttl, state: map[string]stateEntry{}}
}

// StartGC fires a ticker that purges expired OAuth state entries every
// `every` interval. Without this the state map would only get pruned
// when a new Authorize request comes in — if nobody starts an OAuth
// flow for hours the abandoned entries linger. Call once at boot;
// caller's context cancellation stops the goroutine.
func (h *Handler) StartGC(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.gcState()
			}
		}
	}()
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

// APListOutput is the admin shape returned by /auth/providers/all — it
// includes the full DB row (secrets aside, those have `json:"-"`).
type APListOutput struct {
	Body struct {
		Success bool       `json:"success"`
		Data    []Provider `json:"data"`
	}
}

// EnabledProviderView is the public shape for /auth/providers — only
// the fields the login page needs to render a provider button. We do
// NOT expose clientId, issuerUrl, redirectUri, autoRegister,
// adminEmailDomains, sortOrder, etc. — those are operational config,
// not user-facing.
//
// AuthURL is the URL the login button redirects to; pointing at the
// OAuth-dance entrypoint registered by RegisterPlain. We emit it as a
// relative path so the browser resolves it against whatever public
// origin the frontend is served from (works for nginx-proxied,
// Traefik-routed, and direct deploys without extra config).
type EnabledProviderView struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	Type        string  `json:"type"`
	Icon        *string `json:"icon,omitempty"`
	AuthURL     string  `json:"authUrl"`
}

// APEnabledListOutput is the response shape for /auth/providers, mapped
// to the frontend's `EnabledProvidersResponse = ApiResponse<EnabledAuthProvider[]>`.
type APEnabledListOutput struct {
	Body struct {
		Success bool                  `json:"success"`
		Data    []EnabledProviderView `json:"data"`
	}
}

func (h *Handler) ListEnabled(ctx context.Context, _ *struct{}) (*APEnabledListOutput, error) {
	out := &APEnabledListOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Data = []EnabledProviderView{}
	rows, err := h.DB.QueryContext(ctx,
		`SELECT id, name, displayName, type, icon FROM auth_providers
		 WHERE enabled = 1 ORDER BY sortOrder ASC`)
	if err != nil {
		return nil, apperr.Internal("list providers: " + err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var v EnabledProviderView
		if err := rows.Scan(&v.ID, &v.Name, &v.DisplayName, &v.Type, &v.Icon); err != nil {
			continue
		}
		v.AuthURL = "/api/auth/providers/" + v.Name + "/authorize"
		out.Body.Data = append(out.Body.Data, v)
	}
	out.Body.Success = true
	return out, nil
}

func (h *Handler) ListAll(ctx context.Context, _ *struct{}) (*APListOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	out := &APListOutput{}
	// Pre-initialise so an empty result serialises as `[]`, not `null`.
	out.Body.Data = []Provider{}
	_ = h.DB.SelectContext(ctx, &out.Body.Data, `
		SELECT id, name, displayName, type, icon, enabled, issuerUrl, clientId, redirectUri, scope,
		       authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt
		FROM auth_providers ORDER BY sortOrder ASC`)
	out.Body.Success = true
	return out, nil
}

// APCreateBody is the request shape for POST /auth/providers. Only the
// fields the frontend's NewProvider type sends are required; everything
// else is optional (pointer or *bool/*int). We can't reuse the DB
// Provider struct here for two reasons:
//
//   1. Its scalar fields (Name, Type, Enabled, AutoRegister, SortOrder)
//      are non-pointer non-omitempty, so huma's generated schema marks
//      them required — even AutoRegister and SortOrder which the admin
//      UI never sends.
//   2. Its ClientSecret carries `json:"-"` to hide it on output, which
//      also blocks deserialization on input.
type APCreateBody struct {
	Name                  string  `json:"name" required:"true"`
	DisplayName           string  `json:"displayName" required:"true"`
	Type                  string  `json:"type" required:"true"`
	Icon                  *string `json:"icon,omitempty"`
	Enabled               *bool   `json:"enabled,omitempty"`
	IssuerURL             *string `json:"issuerUrl,omitempty"`
	ClientID              string  `json:"clientId" required:"true"`
	ClientSecret          string  `json:"clientSecret" required:"true"`
	RedirectURI           *string `json:"redirectUri,omitempty"`
	Scope                 *string `json:"scope,omitempty"`
	AuthorizationEndpoint *string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         *string `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint      *string `json:"userInfoEndpoint,omitempty"`
	Metadata              *string `json:"metadata,omitempty"`
	AutoRegister          *bool   `json:"autoRegister,omitempty"`
	AdminEmailDomains     *string `json:"adminEmailDomains,omitempty"`
	SortOrder             *int    `json:"sortOrder,omitempty"`
}

// APUpdateBody is the request shape for PUT /auth/providers/{id}. All
// fields are optional — unset fields fall back to whatever the existing
// row already has, so the admin UI can edit one attribute without
// re-sending the rest (in particular, ClientSecret stays put when the
// admin leaves the field empty).
type APUpdateBody struct {
	Name                  *string `json:"name,omitempty"`
	DisplayName           *string `json:"displayName,omitempty"`
	Type                  *string `json:"type,omitempty"`
	Icon                  *string `json:"icon,omitempty"`
	Enabled               *bool   `json:"enabled,omitempty"`
	IssuerURL             *string `json:"issuerUrl,omitempty"`
	ClientID              *string `json:"clientId,omitempty"`
	ClientSecret          *string `json:"clientSecret,omitempty"`
	RedirectURI           *string `json:"redirectUri,omitempty"`
	Scope                 *string `json:"scope,omitempty"`
	AuthorizationEndpoint *string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         *string `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint      *string `json:"userInfoEndpoint,omitempty"`
	Metadata              *string `json:"metadata,omitempty"`
	AutoRegister          *bool   `json:"autoRegister,omitempty"`
	AdminEmailDomains     *string `json:"adminEmailDomains,omitempty"`
	SortOrder             *int    `json:"sortOrder,omitempty"`
}

type APCreateInput struct{ Body APCreateBody }

// APSingleOutput matches the frontend's `AuthProviderResponse = ApiResponse<AuthProvider>`
// envelope — i.e. `{ success: true, data: AuthProvider }`. The whole settings UI
// branches on `response.data.success`, so omitting that field makes successful
// 200s look like failures and triggers the "update failed" toast.
type APSingleOutput struct {
	Body struct {
		Success bool     `json:"success"`
		Data    Provider `json:"data"`
	}
}

func (b APCreateBody) toProvider() Provider {
	cid, cs := b.ClientID, b.ClientSecret
	p := Provider{
		Name:         b.Name,
		DisplayName:  b.DisplayName,
		Type:         b.Type,
		Icon:         b.Icon,
		IssuerURL:    b.IssuerURL,
		ClientID:     &cid,
		ClientSecret: &cs,
		RedirectURI:  b.RedirectURI,
		Scope:        b.Scope,
		AuthorizationEndpoint: b.AuthorizationEndpoint,
		TokenEndpoint:         b.TokenEndpoint,
		UserInfoEndpoint:      b.UserInfoEndpoint,
		Metadata:              b.Metadata,
		AdminEmailDomains:     b.AdminEmailDomains,
	}
	if b.Enabled != nil {
		p.Enabled = *b.Enabled
	}
	if b.AutoRegister != nil {
		p.AutoRegister = *b.AutoRegister
	}
	if b.SortOrder != nil {
		p.SortOrder = *b.SortOrder
	}
	return p
}

func (b APUpdateBody) applyTo(p *Provider) {
	if b.Name != nil {
		p.Name = *b.Name
	}
	if b.DisplayName != nil {
		p.DisplayName = *b.DisplayName
	}
	if b.Type != nil {
		p.Type = *b.Type
	}
	if b.Icon != nil {
		p.Icon = b.Icon
	}
	if b.Enabled != nil {
		p.Enabled = *b.Enabled
	}
	if b.IssuerURL != nil {
		p.IssuerURL = b.IssuerURL
	}
	if b.ClientID != nil {
		p.ClientID = b.ClientID
	}
	// Treat empty clientSecret as "don't change" — the admin UI sends an
	// empty string when the user hasn't typed a new value, and we don't
	// want to wipe the stored secret in that case.
	if b.ClientSecret != nil && *b.ClientSecret != "" {
		s := *b.ClientSecret
		p.ClientSecret = &s
	}
	if b.RedirectURI != nil {
		p.RedirectURI = b.RedirectURI
	}
	if b.Scope != nil {
		p.Scope = b.Scope
	}
	if b.AuthorizationEndpoint != nil {
		p.AuthorizationEndpoint = b.AuthorizationEndpoint
	}
	if b.TokenEndpoint != nil {
		p.TokenEndpoint = b.TokenEndpoint
	}
	if b.UserInfoEndpoint != nil {
		p.UserInfoEndpoint = b.UserInfoEndpoint
	}
	if b.Metadata != nil {
		p.Metadata = b.Metadata
	}
	if b.AutoRegister != nil {
		p.AutoRegister = *b.AutoRegister
	}
	if b.AdminEmailDomains != nil {
		p.AdminEmailDomains = b.AdminEmailDomains
	}
	if b.SortOrder != nil {
		p.SortOrder = *b.SortOrder
	}
}

func (h *Handler) Create(ctx context.Context, in *APCreateInput) (*APSingleOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	p := in.Body.toProvider()
	if err := validateProviderEndpoints(p); err != nil {
		return nil, err
	}
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
	out.Body.Success = true
	out.Body.Data = p
	return out, nil
}

type APUpdateInput struct {
	ID   string `path:"id"`
	Body APUpdateBody
}

func (h *Handler) Update(ctx context.Context, in *APUpdateInput) (*APSingleOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	// Load the existing row first so unset fields fall back to current
	// values (partial update semantics).
	var p Provider
	if err := h.DB.GetContext(ctx, &p, `
		SELECT id, name, displayName, type, icon, enabled, issuerUrl, clientId, clientSecret, redirectUri, scope,
		       authorizationEndpoint, tokenEndpoint, userInfoEndpoint, metadata, autoRegister, adminEmailDomains, sortOrder, createdAt, updatedAt
		FROM auth_providers WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.NotFound("provider not found")
	}
	in.Body.applyTo(&p)
	if err := validateProviderEndpoints(p); err != nil {
		return nil, err
	}
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
	out.Body.Success = true
	out.Body.Data = p
	return out, nil
}

type APReorderEntry struct {
	ID        string `json:"id"`
	SortOrder int    `json:"sortOrder"`
}
type APReorderInput struct {
	Body struct {
		Providers []APReorderEntry `json:"providers"`
	}
}
// APMsgOutput matches the frontend's `ApiMessageResponse = { success, message }`
// envelope. The settings UI branches on `data.success` for Reorder/Delete just
// like it does for Create/Update.
type APMsgOutput struct {
	Body struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

func (h *Handler) Reorder(ctx context.Context, in *APReorderInput) (*APMsgOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	tx, err := h.DB.BeginTxx(ctx, nil)
	if err != nil {
		return nil, apperr.Internal("begin")
	}
	defer tx.Rollback()
	for _, p := range in.Body.Providers {
		dbtypes.LogBestEffort(ctx, "authproviders.authproviders.update.auth_providers.set.sortorder", tx, `UPDATE auth_providers SET sortOrder=? WHERE id=?`, p.SortOrder, p.ID)
	}
	if err := tx.Commit(); err != nil {
		return nil, apperr.Internal("commit")
	}
	out := &APMsgOutput{}
	out.Body.Success = true
	out.Body.Message = "reordered"
	return out, nil
}

type APDeleteInput struct{ ID string `path:"id"` }

func (h *Handler) Delete(ctx context.Context, in *APDeleteInput) (*APMsgOutput, error) {
	if _, err := auth.EnsureAdmin(ctx, h.DB); err != nil {
		return nil, apperr.Unauthorized(err.Error())
	}
	if _, err := h.DB.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = ?`, in.ID); err != nil {
		return nil, apperr.Internal("delete provider")
	}
	out := &APMsgOutput{}
	out.Body.Success = true
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
		apperr.WriteJSON(w, http.StatusNotFound, "provider not found or disabled")
		return
	}
	verifier, challenge := pkcePair()
	stateID := genState()
	h.stateMu.Lock()
	h.state[stateID] = stateEntry{Provider: name, CodeVerifier: verifier, CreatedAt: time.Now()}
	h.stateMu.Unlock()
	// State map is GC'd by a periodic ticker started in StartGC at boot —
	// no need to fire one here too.

	conf, ctx := h.oauth2Config(r.Context(), p)
	_ = ctx
	// Auto-set the callback URL when the provider row doesn't carry one.
	// Required by spec-strict IdPs (defguard, Cognito with policy, …);
	// the same value MUST be replayed at token exchange in Callback.
	conf.RedirectURL = h.effectiveRedirectURI(r, name, p)
	url := conf.AuthCodeURL(stateID,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, r, url, http.StatusFound)
}

// effectiveRedirectURI returns the OAuth callback URL to advertise to
// the IdP. Admin-configured `redirectUri` wins (override path); the
// default is reconstructed from the current request — public scheme +
// host from forwarded headers + the chi route for /callback.
//
// Resolving from the request rather than baking it at install lets
// Palmr work behind any reverse proxy hostname without a config edit.
func (h *Handler) effectiveRedirectURI(r *http.Request, providerName string, p Provider) string {
	if p.RedirectURI != nil && *p.RedirectURI != "" {
		return *p.RedirectURI
	}
	return h.frontendURL(r) + "/api/auth/providers/" + providerName + "/callback"
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	stateID := r.URL.Query().Get("state")

	// Pop the state entry atomically so a replay of the same callback
	// URL doesn't reuse it.
	h.stateMu.Lock()
	st, ok := h.state[stateID]
	if ok {
		delete(h.state, stateID)
	}
	h.stateMu.Unlock()
	if !ok || st.Provider != name {
		apperr.WriteJSON(w, http.StatusBadRequest, "invalid state")
		return
	}
	// SECURITY: enforce the state expiry inline rather than leaning
	// on the 5-minute GC ticker. Otherwise a captured state value
	// stays replayable for up to one GC cycle (~5 min) after the
	// authorize step, which is much longer than the ~30-60s an OAuth
	// flow takes in practice. The 10-minute window matches gcState's
	// cutoff and covers slow human MFA prompts.
	if time.Since(st.CreatedAt) > 10*time.Minute {
		apperr.WriteJSON(w, http.StatusBadRequest, "state expired; restart the login flow")
		return
	}

	p, err := h.loadByName(r.Context(), name)
	if err != nil || !p.Enabled {
		apperr.WriteJSON(w, http.StatusNotFound, "provider not found")
		return
	}

	conf, ctx := h.oauth2Config(r.Context(), p)
	// Replay the exact redirect_uri sent on the authorize step — the
	// OAuth2 spec requires the IdP to verify it matches. With a nil
	// `p.RedirectURI` both sides resolve through effectiveRedirectURI()
	// so the host/scheme is consistent (assuming the proxy didn't
	// swap behind our back between the two hops).
	conf.RedirectURL = h.effectiveRedirectURI(r, name, p)
	// Inject a logging HTTP client so a failed token exchange (the
	// most common spot for opaque OAuth bugs) writes the request +
	// response to the server log. Client secret is masked on the way
	// out so the log stays grep-friendly without leaking the secret.
	//
	// SECURITY: the underlying transport is safeHTTPClient.Transport
	// — same private-IP refusal as the rest of the OIDC outbound
	// path. Don't replace with http.DefaultTransport.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Timeout:   10 * time.Second,
		Transport: &oidcDebugTransport{base: safeHTTPClient.Transport, provider: name},
	})
	tok, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", st.CodeVerifier))
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "token exchange: "+err.Error())
		return
	}

	// Pull userinfo. If the provider has an OIDC issuer we use go-oidc;
	// otherwise we hit userInfoEndpoint directly.
	identity, err := h.fetchIdentity(ctx, p, tok)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "userinfo: "+err.Error())
		return
	}
	if identity.Email == "" || identity.Subject == "" {
		apperr.WriteJSON(w, http.StatusBadGateway, "missing claims")
		return
	}

	// Link or create user.
	userID, isAdmin, err := h.linkOrCreate(r.Context(), p, identity)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	jwtStr, err := h.Signer.Sign(userID, isAdmin)
	if err != nil {
		apperr.WriteJSON(w, http.StatusInternalServerError, "issue token: "+err.Error())
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
	}

	rawIssuer := deref(p.IssuerURL)
	trimmedIssuer := strings.TrimRight(rawIssuer, "/")

	// Prefer OIDC discovery — one round-trip and the IdP can rev its
	// endpoint URLs without an admin edit on our side.
	if rawIssuer != "" {
		if prov, err := discoverOIDCProvider(ctx, rawIssuer); err == nil {
			conf.Endpoint = prov.Endpoint()
			conf.Endpoint.AuthStyle = oauth2.AuthStyleInParams
			return conf, ctx
		}
		// Discovery failed (network error, missing /.well-known/
		// openid-configuration, non-OIDC IdP, …). Fall through to the
		// admin-configured manual endpoints — but resolve them against
		// the issuer URL so a relative path like `/oauth/authorize`
		// still ends up at the IdP. Without this fallback the browser
		// would resolve "/oauth/authorize" against the Palmr origin
		// itself and 404 immediately.
	}

	conf.Endpoint = oauth2.Endpoint{
		AuthURL:  resolveAgainstIssuer(trimmedIssuer, deref(p.AuthorizationEndpoint)),
		TokenURL: resolveAgainstIssuer(trimmedIssuer, deref(p.TokenEndpoint)),
		// Force credentials into the form body. The Go oauth2 lib's
		// default AuthStyleAutoDetect tries Basic Auth first and only
		// retries with body creds on a 401 from the IdP. defguard (and
		// a few others) returns 400 BadRequest when Basic Auth client
		// lookup fails — Go never retries with the body, the request
		// arrives with no resolvable client, and defguard's catch-all
		// returns the misleading `unsupported_grant_type` error.
		AuthStyle: oauth2.AuthStyleInParams,
	}
	return conf, ctx
}

// discoverOIDCProvider runs OIDC discovery, retrying once with a
// toggled trailing slash on the issuer URL. The go-oidc lib does a
// byte-exact comparison between the URL passed here and the `issuer`
// claim returned by the IdP's /.well-known/openid-configuration; some
// IdPs (defguard 1.6 is a known case) advertise the issuer with a
// trailing slash even when the admin configured the URL without one,
// and vice versa, so a plain literal compare false-rejects what is
// the same logical issuer. Retrying with the slash toggled covers both
// directions without dropping the issuer check entirely.
//
// SECURITY: go-oidc uses the http.Client stored in the context via
// oidc.ClientContext for discovery, JWKS fetch, and UserInfo. We
// inject safeHTTPClient here so all of those obey the same private-IP
// refusal as fetchIdentityManual — without it, a compromised admin
// could still pivot through discovery to internal services.
func discoverOIDCProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	ctx = oidc.ClientContext(ctx, safeHTTPClient)
	prov, firstErr := oidc.NewProvider(ctx, issuer)
	if firstErr == nil {
		return prov, nil
	}
	alt := strings.TrimRight(issuer, "/")
	if alt == issuer {
		alt = issuer + "/"
	}
	if alt != issuer {
		if prov, err := oidc.NewProvider(ctx, alt); err == nil {
			return prov, nil
		}
	}
	return nil, firstErr
}

// resolveAgainstIssuer prefixes a relative endpoint path with the
// issuer URL. Absolute URLs and empty strings pass through unchanged.
// Used for the rare case where OIDC discovery fails or the admin
// configured a non-OIDC provider with manual endpoint paths.
func resolveAgainstIssuer(issuer, endpoint string) string {
	if endpoint == "" || strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	if issuer == "" {
		return endpoint
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	return issuer + endpoint
}

// oidcIdentity is what fetchIdentity returns. `EmailVerified` is the
// claim of the same name from id_token or /userinfo — when false (or
// missing) we refuse to link the OIDC sub to an existing local user
// by email, since an attacker could otherwise register an unverified
// `admin@palmr.tld` at the IdP and inherit the local admin row.
type oidcIdentity struct {
	Email         string
	Subject       string
	EmailVerified bool
}

// oidcClaims are the fields we extract from id_token / userinfo. We
// keep email_verified as a pointer so we can distinguish absent
// (treat as not verified) from explicit false.
type oidcClaims struct {
	Email         string `json:"email"`
	Subject       string `json:"sub"`
	EmailVerified *bool  `json:"email_verified"`
}

func (h *Handler) fetchIdentity(ctx context.Context, p Provider, tok *oauth2.Token) (oidcIdentity, error) {
	rawIssuer := deref(p.IssuerURL)

	// Force every go-oidc outbound call (discovery, JWKS for token
	// verification, /userinfo) through safeHTTPClient. Otherwise
	// go-oidc reads the client off ctx via oidc.ClientContext, and
	// without this wrap it falls back to http.DefaultClient which has
	// no SSRF protection.
	ctx = oidc.ClientContext(ctx, safeHTTPClient)

	// Prefer OIDC discovery — id-token verification + userinfo come
	// for free. Falls through to the manual /userinfo path if the IdP
	// doesn't expose /.well-known/openid-configuration at the
	// configured issuer URL.
	if rawIssuer != "" {
		if prov, err := discoverOIDCProvider(ctx, rawIssuer); err == nil {
			rawID, ok := tok.Extra("id_token").(string)
			if ok && rawID != "" {
				verifier := prov.Verifier(&oidc.Config{ClientID: deref(p.ClientID)})
				if idTok, err := verifier.Verify(ctx, rawID); err == nil {
					var c oidcClaims
					if err := idTok.Claims(&c); err == nil && c.Email != "" {
						return oidcIdentity{
							Email:         strings.ToLower(c.Email),
							Subject:       c.Subject,
							EmailVerified: c.EmailVerified != nil && *c.EmailVerified,
						}, nil
					}
				}
			}
			ui, err := prov.UserInfo(ctx, oauth2.StaticTokenSource(tok))
			if err == nil {
				var c oidcClaims
				if err := ui.Claims(&c); err == nil {
					return oidcIdentity{
						Email:         strings.ToLower(c.Email),
						Subject:       c.Subject,
						EmailVerified: c.EmailVerified != nil && *c.EmailVerified,
					}, nil
				}
			}
		}
	}

	// Manual userinfo fallback. Used when:
	//   * No issuerUrl is configured (plain OAuth2 provider), or
	//   * Discovery against the issuer URL failed (404, wrong path,
	//     etc.) — in which case the admin probably configured
	//     userInfoEndpoint manually to compensate.
	return h.fetchIdentityManual(ctx, p, tok)
}

// fetchIdentityManual hits the admin-configured userInfoEndpoint with
// the access token and pulls the standard `email`, `sub`, and
// `email_verified` claims out of the JSON response. Path-relative
// endpoints are resolved against the issuer URL.
func (h *Handler) fetchIdentityManual(ctx context.Context, p Provider, tok *oauth2.Token) (oidcIdentity, error) {
	issuer := strings.TrimRight(deref(p.IssuerURL), "/")
	uiURL := resolveAgainstIssuer(issuer, deref(p.UserInfoEndpoint))
	if uiURL == "" {
		return oidcIdentity{}, apperr.BadRequest("provider has no userInfoEndpoint configured")
	}
	if !strings.HasPrefix(uiURL, "http://") && !strings.HasPrefix(uiURL, "https://") {
		return oidcIdentity{}, apperr.BadRequest("userInfoEndpoint is relative but no issuerUrl is set to resolve it")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uiURL, nil)
	if err != nil {
		return oidcIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	// safeHTTPClient refuses to dial private/loopback/link-local IPs and
	// re-checks at connect time (DNS rebinding defence). See validate
	// ProviderEndpoints + safeHTTPClient docstrings below.
	resp, err := safeHTTPClient.Do(req)
	if err != nil {
		return oidcIdentity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// SECURITY: do NOT reflect the upstream body into our error.
		// `IssuerURL`/`UserInfoEndpoint` are admin-configured, which
		// means a careless or malicious admin can point them at an
		// internal HTTP service; including the response body in the
		// caller-visible error turns blind SSRF into an oracle.
		return oidcIdentity{}, fmt.Errorf("userinfo upstream returned %d", resp.StatusCode)
	}
	var c oidcClaims
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return oidcIdentity{}, err
	}
	if c.Email == "" {
		return oidcIdentity{}, fmt.Errorf("userinfo response missing email claim")
	}
	return oidcIdentity{
		Email:         strings.ToLower(c.Email),
		Subject:       c.Subject,
		EmailVerified: c.EmailVerified != nil && *c.EmailVerified,
	}, nil
}

func (h *Handler) linkOrCreate(ctx context.Context, p Provider, id oidcIdentity) (string, bool, error) {
	// 1) Existing link by (providerId, externalId)? The subject claim
	//    is IdP-issued and immutable — safe to trust regardless of
	//    email_verified.
	var userID string
	err := h.DB.GetContext(ctx, &userID,
		`SELECT userId FROM user_auth_providers WHERE providerId = ? AND externalId = ?`, p.ID, id.Subject)
	if err == nil {
		var isAdmin bool
		_ = h.DB.GetContext(ctx, &isAdmin, `SELECT isAdmin FROM users WHERE id = ?`, userID)
		return userID, isAdmin, nil
	}
	// 2) User exists by email?
	//    SECURITY: refuse to link by email unless the IdP says the
	//    email is verified. Otherwise any attacker who can register
	//    `admin@palmr.tld` at the IdP (without proving control of the
	//    mailbox — common on self-hosted IdPs, social logins without
	//    verification, federated SAML→OIDC bridges) inherits the
	//    existing local row, including its admin flag.
	err = h.DB.GetContext(ctx, &userID, `SELECT id FROM users WHERE email = ?`, id.Email)
	if err == nil {
		if !id.EmailVerified {
			return "", false, apperr.Forbidden(
				"an account with this email already exists; the identity provider has not " +
					"confirmed that you control this email, so it cannot be linked automatically")
		}
		dbtypes.LogBestEffort(ctx, "authproviders.link_existing_user", h.DB,
			`INSERT INTO user_auth_providers (id, userId, providerId, externalId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
			uuid.NewString(), userID, p.ID, id.Subject, time.Now(), time.Now())
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
	// AdminEmailDomains lets the operator say "anyone with this email
	// domain becomes admin". Only honour it when the email is
	// verified — otherwise an IdP that lets users set arbitrary
	// unverified emails would be an admin-escalation surface.
	if id.EmailVerified && p.AdminEmailDomains != nil {
		for _, d := range strings.Split(*p.AdminEmailDomains, ",") {
			if strings.EqualFold(strings.TrimSpace(d), strings.SplitN(id.Email, "@", 2)[1]) {
				isAdmin = true
				break
			}
		}
	}
	username := strings.SplitN(id.Email, "@", 2)[0]
	now := time.Now().UTC()
	_, err = h.DB.ExecContext(ctx, `
		INSERT INTO users (id, firstName, lastName, username, email, isAdmin, isActive, createdAt, updatedAt, twoFactorEnabled, twoFactorVerified)
		VALUES (?, ?, '', ?, ?, ?, 1, ?, ?, 0, 0)`,
		uid, username, username, id.Email, isAdmin, now, now)
	if err != nil {
		return "", false, apperr.Internal("auto-register: " + err.Error())
	}
	dbtypes.LogBestEffort(ctx, "authproviders.link_new_user", h.DB,
		`INSERT INTO user_auth_providers (id, userId, providerId, externalId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), uid, p.ID, id.Subject, now, now)
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

// frontendURL reconstructs the public URL of the frontend from the
// incoming request. It is used to build the post-OAuth redirect target
// (e.g. "https://palmr.example.com/auth/callback") and the
// auto-generated OAuth redirect_uri.
//
// Port-stripping policy:
//
//   * X-Forwarded-Port wins when present — trust the edge proxy.
//   * Otherwise, if the scheme is HTTPS and the host carries any
//     non-standard port, strip it. The most common reason a port ends
//     up in Host / X-Forwarded-Host here is a proxy chain (Cloudflare /
//     host-nginx → host:5487 → Traefik → palmr-web nginx) where the
//     outer proxy forwards the *upstream* URL rather than the
//     *original* one, so what arrives is `partagev2.example.com:5487`
//     even though the browser asked for plain `partagev2.example.com`.
//     Stripping it makes the redirect land back on the same origin
//     the user came from. If the operator legitimately runs HTTPS on
//     :8443, they should set X-Forwarded-Port at the edge.
//   * Plain HTTP keeps the port — `http://localhost:5487` is a valid
//     dev URL we don't want to mangle.
func (h *Handler) frontendURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = strings.SplitN(v, ",", 2)[0]
	}

	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = strings.SplitN(v, ",", 2)[0]
	}
	host = strings.TrimSpace(host)

	if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); xfp != "" {
		// Explicit signal from the edge — strip whatever port is on
		// host and re-append the forwarded one, unless it's the
		// scheme default.
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if (scheme == "https" && xfp != "443") || (scheme == "http" && xfp != "80") {
			host = host + ":" + xfp
		}
	} else if scheme == "https" {
		// Heuristic strip: HTTPS + any non-443 port is almost always
		// a leak of an internal proxy chain port. See comment block
		// above for the rationale.
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
	}

	return scheme + "://" + host
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (h *Handler) gcState() {
	cutoff := time.Now().Add(-10 * time.Minute)
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
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

// -----------------------------------------------------------------------------
// SSRF defence
// -----------------------------------------------------------------------------

// validateProviderEndpoints rejects admin-supplied provider URLs that
// point at private / loopback / link-local / multicast / unspecified
// address ranges. Required because the OIDC handshake makes the
// backend issue outbound HTTP requests to IssuerURL +
// AuthorizationEndpoint + TokenEndpoint + UserInfoEndpoint — without
// validation, a careless or compromised admin could aim those at the
// cloud-metadata service (169.254.169.254), the host's localhost
// services, RFC1918 internal hosts, etc. We refuse non-http(s)
// schemes too (file:, gopher:, ftp:).
func validateProviderEndpoints(p Provider) error {
	urls := []struct {
		field string
		value *string
	}{
		{"issuerUrl", p.IssuerURL},
		{"authorizationEndpoint", p.AuthorizationEndpoint},
		{"tokenEndpoint", p.TokenEndpoint},
		{"userInfoEndpoint", p.UserInfoEndpoint},
		{"redirectUri", p.RedirectURI},
	}
	for _, u := range urls {
		if u.value == nil || *u.value == "" {
			continue
		}
		raw := strings.TrimSpace(*u.value)
		// Relative endpoint paths are resolved against IssuerURL at
		// fetch time — they can't reach a different host on their own,
		// so skip the host validation here.
		if strings.HasPrefix(raw, "/") {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return apperr.BadRequest(u.field + " is not a valid URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return apperr.BadRequest(u.field + " must be http or https")
		}
		host := parsed.Hostname()
		if host == "" {
			return apperr.BadRequest(u.field + " has no host")
		}
		if isPrivateHost(host) {
			return apperr.BadRequest(u.field + " points to a private/loopback address")
		}
	}
	return nil
}

// isPrivateHost returns true when the literal IP — or every IP a name
// resolves to — falls inside a range we refuse to call out to.
// Hostnames that don't resolve are conservatively rejected; the admin
// can fix the DNS or use the IP literal.
func isPrivateHost(host string) bool {
	// Strip an IPv6 bracketed form.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	// localhost-by-name covers the case where /etc/hosts maps it but
	// we don't want to lean on a DNS round-trip in the validator.
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return true // can't verify — refuse
	}
	for _, a := range addrs {
		if isPrivateIP(a) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	return false
}

// safeHTTPClient is the http.Client we use for OIDC outbound requests.
// Its Transport is built on a Dialer that re-validates every resolved
// address right before connecting — defence against DNS rebinding
// where the hostname was healthy at config-write time but flips to
// 127.0.0.1 on the actual request.
var safeHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil || len(addrs) == 0 {
					return nil, fmt.Errorf("dns lookup failed for %s", host)
				}
				for _, a := range addrs {
					if isPrivateIP(a.IP) {
						return nil, fmt.Errorf("refusing to connect to private address %s", a.IP)
					}
				}
				ip = addrs[0].IP
			} else if isPrivateIP(ip) {
				return nil, fmt.Errorf("refusing to connect to private address %s", ip)
			}
			var d net.Dialer
			d.Timeout = 10 * time.Second
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// -----------------------------------------------------------------------------
// OAuth diagnostics
// -----------------------------------------------------------------------------

// oidcDebugTransport wraps an http.RoundTripper to log the request +
// response when the upstream IdP returns a non-2xx. Plugged into the
// token-exchange call via context-injected oauth2.HTTPClient. We log
// on failure only because successful flows are noise-free and our
// secret is in the body (we'd rather not write it to stdout on
// happy-path).
//
// `client_secret`, `code`, and `code_verifier` are masked before
// logging — these are PKCE / OAuth secrets we don't want grep'ing
// out of container logs.
type oidcDebugTransport struct {
	base     http.RoundTripper
	provider string
}

func (t *oidcDebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Capture the request body up-front so we can log it after the
	// round-trip (req.Body is normally consumed by RoundTrip).
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		slog.Error("oidc token exchange transport error",
			"provider", t.provider, "url", req.URL.String(), "err", err.Error())
		return resp, err
	}
	if resp.StatusCode < 400 {
		return resp, err
	}
	// Drain + restore response body so the oauth2 lib still sees it.
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	slog.Error("oidc token exchange failed",
		"provider", t.provider,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"request_body", maskOAuthSecrets(string(reqBody)),
		"request_basic_auth", req.Header.Get("Authorization") != "",
		"response_body", string(respBody),
	)
	return resp, err
}

// maskOAuthSecrets replaces secret-bearing form fields with `***` so
// the log line stays readable without leaking credentials.
func maskOAuthSecrets(body string) string {
	if body == "" {
		return ""
	}
	vals, err := url.ParseQuery(body)
	if err != nil {
		return "<unparseable form>"
	}
	for _, k := range []string{"client_secret", "code", "code_verifier", "refresh_token"} {
		if vals.Has(k) {
			vals.Set(k, "***")
		}
	}
	return vals.Encode()
}
