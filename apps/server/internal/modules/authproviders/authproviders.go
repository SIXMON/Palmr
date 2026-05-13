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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	tok, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", st.CodeVerifier))
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "token exchange: "+err.Error())
		return
	}

	// Pull userinfo. If the provider has an OIDC issuer we use go-oidc;
	// otherwise we hit userInfoEndpoint directly.
	email, sub, err := h.fetchIdentity(ctx, p, tok)
	if err != nil {
		apperr.WriteJSON(w, http.StatusBadGateway, "userinfo: "+err.Error())
		return
	}
	if email == "" || sub == "" {
		apperr.WriteJSON(w, http.StatusBadGateway, "missing claims")
		return
	}

	// Link or create user.
	userID, isAdmin, err := h.linkOrCreate(r.Context(), p, email, sub)
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
func discoverOIDCProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
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

func (h *Handler) fetchIdentity(ctx context.Context, p Provider, tok *oauth2.Token) (email, sub string, err error) {
	rawIssuer := deref(p.IssuerURL)

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
					var c struct {
						Email   string `json:"email"`
						Subject string `json:"sub"`
					}
					if err := idTok.Claims(&c); err == nil && c.Email != "" {
						return strings.ToLower(c.Email), c.Subject, nil
					}
				}
			}
			ui, err := prov.UserInfo(ctx, oauth2.StaticTokenSource(tok))
			if err == nil {
				var c struct {
					Email   string `json:"email"`
					Subject string `json:"sub"`
				}
				if err := ui.Claims(&c); err == nil {
					return strings.ToLower(c.Email), c.Subject, nil
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
// the access token and pulls the standard `email` and `sub` claims out
// of the JSON response. Path-relative endpoints are resolved against
// the issuer URL.
func (h *Handler) fetchIdentityManual(ctx context.Context, p Provider, tok *oauth2.Token) (email, sub string, err error) {
	issuer := strings.TrimRight(deref(p.IssuerURL), "/")
	uiURL := resolveAgainstIssuer(issuer, deref(p.UserInfoEndpoint))
	if uiURL == "" {
		return "", "", apperr.BadRequest("provider has no userInfoEndpoint configured")
	}
	if !strings.HasPrefix(uiURL, "http://") && !strings.HasPrefix(uiURL, "https://") {
		return "", "", apperr.BadRequest("userInfoEndpoint is relative but no issuerUrl is set to resolve it")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", "", fmt.Errorf("userinfo %d: %s", resp.StatusCode, string(body))
	}
	var c struct {
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return "", "", err
	}
	if c.Email == "" {
		return "", "", fmt.Errorf("userinfo response missing email claim")
	}
	return strings.ToLower(c.Email), c.Subject, nil
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
		dbtypes.LogBestEffort(ctx, "authproviders.link_existing_user", h.DB,
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
	dbtypes.LogBestEffort(ctx, "authproviders.link_new_user", h.DB,
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
