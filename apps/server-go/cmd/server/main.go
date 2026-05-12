// Palmr Go backend — entrypoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/sixmon/palmr/apps/server-go/internal/auth"
	"github.com/sixmon/palmr/apps/server-go/internal/config"
	"github.com/sixmon/palmr/apps/server-go/internal/db"
	"github.com/sixmon/palmr/apps/server-go/internal/logger"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/app"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/authn"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/authproviders"
	embedmod "github.com/sixmon/palmr/apps/server-go/internal/modules/embed"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/email"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/file"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/folder"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/health"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/invite"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/reverseshare"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/share"
	storagemod "github.com/sixmon/palmr/apps/server-go/internal/modules/storage"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/twofactor"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/uploads"
	"github.com/sixmon/palmr/apps/server-go/internal/modules/user"
	"github.com/sixmon/palmr/apps/server-go/internal/storage"
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
	shareHandler := &share.Handler{DB: conn}
	share.Register(api, shareHandler)

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
					req = r.WithContext(auth.WithUser(r.Context(), auth.UserCtx{
						UserID:  claims.UserID,
						IsAdmin: claims.IsAdmin,
						Active:  true,
						JTI:     claims.JTI,
					}))
				}
			}
			next.ServeHTTP(w, req)
		})
	}
}

func corsMiddleware(allow []string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, o := range allow {
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
