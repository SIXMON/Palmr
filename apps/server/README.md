# Palmr backend (Go)

The backend service for Palmr. Single static binary built `FROM scratch`
(~20 MB final image: ca-certs + binary + seed JSONs, no shell, no libc,
no package manager). Pure-Go SQLite driver (`modernc.org/sqlite`) makes
the scratch base possible.

The schema is managed in-process by `pressly/goose` migrations under
`internal/db/migrations/`. The first migration imports the legacy
Prisma schema layout; later migrations are additive.

## Build & run

You need Docker; Go isn't required on the host (the builder image has it).

```sh
docker compose up -d
```

The compose stack brings up MinIO + Traefik + this service + the
frontend. See the root `docker-compose.yaml` for env-var requirements
(JWT_SECRET, CORS_ALLOWED_ORIGINS, STORAGE_URL, etc.).

Direct API access is internal-only by default; uncomment the `ports:`
block in the compose file to publish 3333 on the host for debugging.

## Local development (host has Go ≥ 1.23 installed)

```sh
cd apps/server
make tidy            # generate go.sum
make run             # go run ./cmd/server
```

The binary reads the SQLite file from `${DATA_DIR}/prisma/palmr.db`
(default `DATA_DIR=./.data`). Set the same env vars the docker-compose
passes.

## Why these choices

| Concern        | Library                       | Why over alternatives                                                                  |
|----------------|-------------------------------|----------------------------------------------------------------------------------------|
| HTTP router    | `chi`                         | stdlib-compatible, minimal, mature                                                     |
| OpenAPI        | `huma/v2`                     | derives schema from Go types                                                           |
| ORM            | `sqlx` + plain SQL            | predictable; no schema duplication                                                     |
| SQLite driver  | `modernc.org/sqlite`          | pure Go → no CGO → `FROM scratch` works                                                |
| Migrations     | `pressly/goose/v3`            | embedded SQL + simple up/down — no separate CLI in the container                       |
| JWT            | `golang-jwt/jwt/v5`           | HS256, same shape as the legacy `jose` setup                                           |
| OIDC           | `coreos/go-oidc/v3`           | battle-tested (Kubernetes, ArgoCD, Dex)                                                |
| S3             | `aws-sdk-go-v2`               | upstream AWS SDK, supports MinIO via custom endpoint                                   |
| TOTP           | `pquerna/otp`                 | same RFC 6238 setup as the legacy `speakeasy`                                          |
| Mail           | `wneessen/go-mail`            | modern API, no implicit globals                                                        |
| QR             | `skip2/go-qrcode`             | pure Go, no native deps                                                                |
| Validation     | huma's struct tags            | enough for the contract — `min`/`max`/`required`/`format`                              |
| Env            | `caarlos0/env/v11`            | struct-tagged, fails fast                                                              |

## Open questions for later

- The jti revocation list is in-memory and single-instance. If Palmr
  ever scales horizontally, swap `auth.RevokeJTI` for a Redis- or
  table-backed store.
- Avatar/logo upload uses the pure-Go `image` package. Pixel-perfect
  parity with libvips can be revisited via `govips` if it ever matters.
