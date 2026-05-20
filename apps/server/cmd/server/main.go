// Palmr Go backend — entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"

	"github.com/sixmon/palmr/apps/server/internal/auth"
	"github.com/sixmon/palmr/apps/server/internal/config"
	"github.com/sixmon/palmr/apps/server/internal/db"
	"github.com/sixmon/palmr/apps/server/internal/logger"
	"github.com/sixmon/palmr/apps/server/internal/modules/app"
	"github.com/sixmon/palmr/apps/server/internal/modules/authn"
	"github.com/sixmon/palmr/apps/server/internal/modules/authproviders"
	embedmod "github.com/sixmon/palmr/apps/server/internal/modules/embed"
	"github.com/sixmon/palmr/apps/server/internal/modules/email"
	"github.com/sixmon/palmr/apps/server/internal/modules/file"
	"github.com/sixmon/palmr/apps/server/internal/modules/folder"
	"github.com/sixmon/palmr/apps/server/internal/modules/health"
	"github.com/sixmon/palmr/apps/server/internal/modules/invite"
	"github.com/sixmon/palmr/apps/server/internal/modules/og"
	"github.com/sixmon/palmr/apps/server/internal/modules/reverseshare"
	"github.com/sixmon/palmr/apps/server/internal/modules/share"
	storagemod "github.com/sixmon/palmr/apps/server/internal/modules/storage"
	"github.com/sixmon/palmr/apps/server/internal/modules/twofactor"
	"github.com/sixmon/palmr/apps/server/internal/modules/uploads"
	"github.com/sixmon/palmr/apps/server/internal/modules/user"
	"github.com/sixmon/palmr/apps/server/internal/storage"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "Exit 0 if the local /health endpoint reports healthy.")
	flag.Parse()
	if *healthcheck {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3333"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func run() error {
	log := logger.Init()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	conn, err := db.Open(ctx, cfg.DataDir)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		return fmt.Errorf("db ping: %w", err)
	}
	// First-boot: create schema and seed app_configs if the DB is empty.
	// Idempotent on populated DBs.
	if err := db.EnsureSchema(ctx, conn, cfg.DataDir); err != nil {
		return fmt.Errorf("ensure schema: %w", err)
	}

	s3client, err := storage.New(ctx, cfg)
	if err != nil {
		log.Warn("S3 not initialised", "err", err)
	}
	// Let /app/system-info reflect whether external S3 is in use.
	app.HasExternalS3 = cfg.EnableS3

	signer := auth.NewSigner(cfg.JWTSecret, cfg.JWTTTL())
	mw := &auth.Middleware{Signer: signer, DB: conn, SecureSite: cfg.SecureSite}

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(corsMiddleware(cfg.AllowedOrigins()))
	r.Use(authOptional(mw))

	api := humachi.New(r, huma.DefaultConfig("Palmr", "1.0.0"))

	// -------------------------------------------------------------------------
	// Public + bootstrap
	// -------------------------------------------------------------------------
	health.Register(api, &health.Handler{DB: conn})
	app.Register(api, &app.Handler{DB: conn})
	// Same Service instance is reused by /app/test-smtp and the password
	// reset flow — share a singleton so the SMTP config is read once per
	// request from the DB (cheap, indexed lookups).
	mailSvc := &email.Service{DB: conn}
	authn.RegisterPublic(api, &authn.Handler{
		DB: conn, Signer: signer, SecureSite: cfg.SecureSite, CookieTTL: cfg.JWTTTL(),
		Mailer: mailSvc,
	})
	user.RegisterPublic(api, &user.Handler{
		DB: conn, Signer: signer, BcryptCost: cfg.BcryptCost,
		SecureSite: cfg.SecureSite, CookieTTL: cfg.JWTTTL(),
	})
	// Share + reverse-share have public endpoints (alias views).
	// share.New initialises the in-memory throttle used by GetByAlias
	// to rate-limit share-password attempts (M1) and wires S3 for the
	// chi-native /shares/alias/{alias}/download endpoint (nginx routes
	// curl/wget hits on /s/{alias} here for direct downloads).
	shareHandler := share.New(conn, s3client)
	share.Register(api, shareHandler)
	shareHandler.RegisterPlain(r)

	rsHandler := &reverseshare.Handler{DB: conn, S3: s3client}
	reverseshare.Register(api, rsHandler)

	// -------------------------------------------------------------------------
	// Authenticated (per-handler auth.EnsureAuth / EnsureAdmin)
	// -------------------------------------------------------------------------
	app.RegisterAdmin(api, &app.Handler{DB: conn})
	user.RegisterAdmin(api, &user.Handler{
		DB: conn, Signer: signer, BcryptCost: cfg.BcryptCost,
		SecureSite: cfg.SecureSite, CookieTTL: cfg.JWTTTL(),
	})
	file.Register(api, &file.Handler{DB: conn, S3: s3client})
	folder.Register(api, &folder.Handler{DB: conn})
	storagemod.Register(api, &storagemod.Handler{DB: conn})
	twofactor.Register(api, &twofactor.Handler{DB: conn, AppName: "Palmr"})
	invite.Register(api, &invite.Handler{DB: conn, BcryptCost: cfg.BcryptCost})
	email.Register(api, &email.Handler{Svc: mailSvc})

	// -------------------------------------------------------------------------
	// OAuth providers — admin CRUD via huma, plus the OAuth dance which
	// uses raw chi handlers (huma doesn't play well with 302 redirects).
	// -------------------------------------------------------------------------
	apHandler := authproviders.New(conn, signer, cfg.SecureSite, cfg.JWTTTL())
	authproviders.Register(api, apHandler)
	apHandler.RegisterPlain(r)
	apHandler.StartGC(ctx, 5*time.Minute) // expire abandoned OAuth state entries

	// -------------------------------------------------------------------------
	// Embed route (raw streaming, not huma)
	// -------------------------------------------------------------------------
	embedH := &embedmod.Handler{DB: conn, S3: s3client}
	embedH.RegisterPlain(r)

	// -------------------------------------------------------------------------
	// OG-tag HTML pages for crawler User-Agents. Wired here (not huma) because
	// the response is HTML, not JSON. nginx splits crawlers off to /og/s/* and
	// /og/r/* via User-Agent matching; humans get the static SPA instead.
	// -------------------------------------------------------------------------
	ogH := &og.Handler{DB: conn}
	ogH.RegisterPlain(r)

	// -------------------------------------------------------------------------
	// Multipart upload routes (avatars + app logo) — chi-native because
	// huma's multipart story isn't mature enough yet.
	// -------------------------------------------------------------------------
	upH := &uploads.Handler{DB: conn, SecureSite: cfg.SecureSite}
	upH.Register(r)

	// JTI sweep
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				auth.SweepRevoked(cfg.JWTTTL() + time.Hour)
			}
		}
	}()

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// -----------------------------------------------------------------------------
// middlewares
// -----------------------------------------------------------------------------

func authOptional(mw *auth.Middleware) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req := r
			if c, err := r.Cookie("token"); err == nil && c.Value != "" {
				if claims, verr := mw.Signer.Verify(c.Value); verr == nil {
					// SECURITY: do NOT trust IsAdmin / IsActive from the
					// JWT alone. The token lives for the full TTL even
					// after the user is demoted or deactivated — without
					// a live DB lookup, revoking admin or freezing an
					// account does nothing until the user logs out and
					// back in. We pay one indexed (`users.id` PK)
					// SELECT per authenticated request to keep this
					// closed; on a DB error or missing row we drop the
					// context entirely (treated as anonymous).
					var row struct {
						IsAdmin  bool `db:"isAdmin"`
						IsActive bool `db:"isActive"`
					}
					if err := mw.DB.GetContext(r.Context(), &row,
						`SELECT isAdmin, isActive FROM users WHERE id = ?`, claims.UserID); err == nil && row.IsActive {
						req = r.WithContext(auth.WithUser(r.Context(), auth.UserCtx{
							UserID:  claims.UserID,
							IsAdmin: row.IsAdmin,
							Active:  true,
							JTI:     claims.JTI,
						}))
						// Bump the user's last-seen timestamp. Surfaced in
						// the admin user-management table; debounced
						// (lastSeenDebounce, in-memory) so a chatty SPA
						// doesn't write every API call.
						bumpLastSeen(r.Context(), mw.DB, claims.UserID)
					}
				}
			}
			next.ServeHTTP(w, req)
		})
	}
}

// lastSeenCache holds the in-memory "we already bumped this user's
// lastSeenAt recently" map. Process-local; on restart we'll do one
// fresh write per active user, which is fine.
//
// Value is the unix-millis timestamp of the last write — we store
// millis rather than time.Time to keep the sync.Map values
// pointer-free (avoids the heap allocation on each store).
var lastSeenCache sync.Map

// lastSeenDebounce is the minimum interval between two writes to a
// given user's lastSeenAt row. Five minutes is short enough that an
// admin watching the user-management table sees presence in near
// real-time, long enough that a polling SPA doesn't cause a write
// storm on the users PK.
const lastSeenDebounce = 5 * time.Minute

// bumpLastSeen is the helper called from authOptional. The DB write
// is fire-and-forget — failure means the next authenticated request
// (5+ minutes later) will retry, which is good enough for a soft
// timestamp like this. We deliberately use the request's context so
// that a client disconnect cancels the write.
func bumpLastSeen(ctx context.Context, db *sqlx.DB, userID string) {
	now := time.Now().UTC()
	nowMs := now.UnixMilli()
	if prev, ok := lastSeenCache.Load(userID); ok {
		if now.Sub(time.UnixMilli(prev.(int64))) < lastSeenDebounce {
			return
		}
	}
	// Set the cache BEFORE the DB write so a burst of concurrent
	// requests after a debounce window expires only triggers one
	// UPDATE (the others see the fresh value and bail). Worst case
	// the UPDATE fails and we wait the next debounce window before
	// trying again.
	lastSeenCache.Store(userID, nowMs)
	_, _ = db.ExecContext(ctx, `UPDATE users SET lastSeenAt = ? WHERE id = ?`, nowMs, userID)
}

func corsMiddleware(allow []string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allow {
		// SECURITY (L6): a bare "*" combined with the
		// `Access-Control-Allow-Credentials: true` header below is
		// rejected by browsers anyway, but more importantly it's
		// almost never what the operator actually wants — they
		// either meant "any subdomain" (which still has to be
		// enumerated) or got the env-var wrong. Refuse to register
		// the wildcard so a misconfigured deploy fails closed
		// instead of silently shipping a broken header.
		if o == "*" {
			continue
		}
		set[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && set[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Share-Password")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
