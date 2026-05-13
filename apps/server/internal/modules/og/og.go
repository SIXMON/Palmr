// Package og serves crawler-targeted HTML pages with dynamic OpenGraph
// tags for shares and reverse-shares. Wired up at:
//
//	GET /og/s/{alias}   — public share preview
//	GET /og/r/{alias}   — reverse-share (upload landing) preview
//
// Why this exists: the frontend ships as a static export from nginx, so
// per-URL <meta property="og:..."> tags can no longer be rendered from
// Next.js at request time. nginx splits crawler User-Agents (Slackbot,
// facebookexternalhit, Twitterbot, Discordbot, etc.) off to these
// endpoints; humans still get the static SPA scaffold and React renders
// the actual page client-side.
//
// The HTML returned here is intentionally minimal — only the <head> and
// a tiny <body> placeholder. Crawlers never execute JS or scroll past
// the head, so there's no reason to ship the React bundle here.
package og

import (
	"context"
	"html/template"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
)

type Handler struct {
	DB *sqlx.DB
}

func (h *Handler) RegisterPlain(r chi.Router) {
	r.Get("/og/s/{alias}", h.share)
	r.Get("/og/r/{alias}", h.reverseShare)
}

// shareView is the data we splice into the HTML template. Empty strings
// fall back to the app defaults via Go template's `{{if .X}}` guards.
type shareView struct {
	Title       string
	Description string
	URL         string
	SiteName    string
	ImageURL    string
}

var ogTmpl = template.Must(template.New("og").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<meta name="description" content="{{.Description}}">
<meta property="og:type" content="website">
<meta property="og:title" content="{{.Title}}">
<meta property="og:description" content="{{.Description}}">
{{if .URL}}<meta property="og:url" content="{{.URL}}">{{end}}
{{if .SiteName}}<meta property="og:site_name" content="{{.SiteName}}">{{end}}
{{if .ImageURL}}<meta property="og:image" content="{{.ImageURL}}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">{{end}}
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{{.Title}}">
<meta name="twitter:description" content="{{.Description}}">
{{if .ImageURL}}<meta name="twitter:image" content="{{.ImageURL}}">{{end}}
</head>
<body>
<noscript><p>This page is rendered for link-unfurl crawlers. <a href="{{.URL}}">Open the share</a>.</p></noscript>
</body>
</html>
`))

func (h *Handler) share(w http.ResponseWriter, r *http.Request) {
	alias := chi.URLParam(r, "alias")
	view := h.loadShare(r.Context(), alias)
	view.URL = absoluteURL(r, "/s/"+alias+"/")
	view.SiteName, view.ImageURL = h.appBranding(r.Context(), r)
	render(w, view)
}

func (h *Handler) reverseShare(w http.ResponseWriter, r *http.Request) {
	alias := chi.URLParam(r, "alias")
	view := h.loadReverseShare(r.Context(), alias)
	view.URL = absoluteURL(r, "/r/"+alias+"/")
	view.SiteName, view.ImageURL = h.appBranding(r.Context(), r)
	render(w, view)
}

// loadShare reads `shares` via the alias join. Empty struct on miss —
// crawlers still get something renderable. Mirrors the totalFiles +
// totalFolders summing done by share.GetAliasMetadata so the description
// matches what bots used to see on the legacy Node frontend.
func (h *Handler) loadShare(ctx context.Context, alias string) shareView {
	var v shareView
	var shareID string
	var name, description *string
	_ = h.DB.QueryRowContext(ctx, `
		SELECT s.id, s.name, s.description
		FROM shares s JOIN share_aliases sa ON sa.shareId = s.id
		WHERE sa.alias = ?`, alias).Scan(&shareID, &name, &description)
	v.Title = strDeref(name, "Share")
	v.Description = strDeref(description, "")
	if v.Description == "" && shareID != "" {
		var files, folders int
		_ = h.DB.GetContext(ctx, &files, `SELECT COUNT(*) FROM _ShareFiles WHERE B = ?`, shareID)
		_ = h.DB.GetContext(ctx, &folders, `SELECT COUNT(*) FROM _ShareFolders WHERE B = ?`, shareID)
		total := files + folders
		if total > 0 {
			v.Description = pluralCount(total, "file", "files") + " shared"
		}
	}
	return v
}

// loadReverseShare matches reverseshare.AliasMetadata: name, description,
// optional maxFiles for the "accepts up to N files" copy.
func (h *Handler) loadReverseShare(ctx context.Context, alias string) shareView {
	var v shareView
	var name, description *string
	var maxFiles *int
	_ = h.DB.QueryRowContext(ctx, `
		SELECT rs.name, rs.description, rs.maxFiles
		FROM reverse_shares rs JOIN reverse_share_aliases a ON a.reverseShareId = rs.id
		WHERE a.alias = ?`, alias).Scan(&name, &description, &maxFiles)
	v.Title = strDeref(name, "Upload")
	v.Description = strDeref(description, "")
	if v.Description == "" {
		if maxFiles != nil && *maxFiles > 0 {
			v.Description = "Upload up to " + pluralCount(*maxFiles, "file", "files")
		} else {
			v.Description = "Send files securely"
		}
	}
	return v
}

func (h *Handler) appBranding(ctx context.Context, r *http.Request) (siteName, imageURL string) {
	_ = h.DB.GetContext(ctx, &siteName, `SELECT value FROM app_configs WHERE key = 'appName'`)
	if siteName == "" {
		siteName = "Palmr"
	}
	var logo string
	_ = h.DB.GetContext(ctx, &logo, `SELECT value FROM app_configs WHERE key = 'appLogo'`)
	if logo == "" {
		return siteName, ""
	}
	// Logos are stored as either a data URI (legacy avatar/logo upload)
	// or an absolute URL. Data URIs work in <meta og:image> for most
	// crawlers but not all; if it's a relative path we anchor it to the
	// requesting Host header so unfurls don't break behind a reverse
	// proxy.
	if strings.HasPrefix(logo, "data:") || strings.HasPrefix(logo, "http://") || strings.HasPrefix(logo, "https://") {
		return siteName, logo
	}
	return siteName, absoluteURL(r, logo)
}

// absoluteURL reconstructs the public URL from forwarded headers.
// Mirrors the port-stripping policy of authproviders.frontendURL() —
// see that function for the rationale. Behind the typical
// Traefik/nginx chain we always see X-Forwarded-Proto and
// X-Forwarded-Host; we fall back to r.Host (no scheme) when those are
// missing.
func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = strings.SplitN(v, ",", 2)[0]
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = strings.SplitN(v, ",", 2)[0]
	}
	host = strings.TrimSpace(host)

	if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); xfp != "" {
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if (scheme == "https" && xfp != "443") || (scheme == "http" && xfp != "80") {
			host = host + ":" + xfp
		}
	} else if scheme == "https" {
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
	}

	return scheme + "://" + host + path
}

func render(w http.ResponseWriter, v shareView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Crawlers cache aggressively; a one-minute TTL keeps stale unfurls
	// from sticking around after a share rename.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = ogTmpl.Execute(w, v)
}

func strDeref(p *string, fallback string) string {
	if p == nil || *p == "" {
		return fallback
	}
	return *p
}

// pluralCount returns "1 file" or "N files" — same rule the frontend
// translations follow for parity with the unfurl text the legacy backend
// produced.
func pluralCount(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return itoa(n) + " " + plural
}

// itoa avoids pulling in strconv for a single call site. Inline because
// the integer is always small (file count).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
