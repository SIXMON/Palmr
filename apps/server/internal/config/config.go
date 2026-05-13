// Package config loads runtime settings from environment variables.
//
// Mirrors apps/server/src/env.ts so the docker-compose can keep the same
// environment block when the legacy backend is replaced.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	// HTTP
	Port           int    `env:"PORT" envDefault:"3333"`
	MaxBodySizeMB  int    `env:"MAX_BODY_SIZE_MB" envDefault:"100"`
	SecureSite     bool   `env:"SECURE_SITE" envDefault:"false"`
	CORSOrigins    string `env:"CORS_ALLOWED_ORIGINS" envDefault:""`

	// Data
	DataDir        string `env:"DATA_DIR" envDefault:"/data"`

	// Auth
	JWTSecret      string `env:"JWT_SECRET,required"`
	BcryptCost     int    `env:"BCRYPT_COST" envDefault:"12"`

	// Object store (S3-compatible)
	EnableS3       bool   `env:"ENABLE_S3" envDefault:"false"`
	S3Endpoint     string `env:"S3_ENDPOINT" envDefault:""`
	S3Port         int    `env:"S3_PORT" envDefault:"0"`
	S3UseSSL       bool   `env:"S3_USE_SSL" envDefault:"false"`
	S3ForcePath    bool   `env:"S3_FORCE_PATH_STYLE" envDefault:"true"`
	S3AccessKey    string `env:"S3_ACCESS_KEY" envDefault:""`
	S3SecretKey    string `env:"S3_SECRET_KEY" envDefault:""`
	S3BucketName   string `env:"S3_BUCKET_NAME" envDefault:""`
	S3Region       string `env:"S3_REGION" envDefault:"us-east-1"`
	S3RejectUnauth bool   `env:"S3_REJECT_UNAUTHORIZED" envDefault:"true"`
	StorageURL     string `env:"STORAGE_URL" envDefault:""`

	// Presigned URL TTL
	PresignedURLTTL int `env:"PRESIGNED_URL_EXPIRATION" envDefault:"3600"`

	// Mail (SMTP) — actual SMTP config lives in DB (configs table), like the
	// legacy backend; only the toggle is here for parity.
}

func Load() (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("env: %w", err)
	}
	// Required-secret length sanity check (matches the legacy 32-char minimum).
	if len(cfg.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters (got %d)", len(cfg.JWTSecret))
	}
	return &cfg, nil
}

func (c *Config) JWTTTL() time.Duration { return 24 * time.Hour }

// AllowedOrigins splits CORS_ALLOWED_ORIGINS into a normalized slice.
func (c *Config) AllowedOrigins() []string {
	if c.CORSOrigins == "" {
		return nil
	}
	out := []string{}
	for _, o := range strings.Split(c.CORSOrigins, ",") {
		if v := strings.TrimSpace(o); v != "" {
			out = append(out, v)
		}
	}
	return out
}
