# Palmr Go backend — Work in progress

A Go rewrite of `apps/server` (Fastify + Prisma). Talks to the **same
SQLite database** as the Node backend (managed by Prisma, schema not
duplicated here), so switching takes a single `docker-compose` change
once the port is feature-complete.

The image is built `FROM scratch`: ~20 MB final, no shell, no libc, no
package manager. Pure-Go SQLite driver (`modernc.org/sqlite`) makes
this possible.

## Status

Currently implemented (MVP — enough to bootstrap an admin):

| Endpoint                          | Method | Notes                              |
|-----------------------------------|--------|------------------------------------|
| `/health`                         | GET    | DB ping                             |
| `/app/info`                       | GET    | name, description, logo, firstUserAccess |
| `/app/configs/public`             | GET    | non-secret configs                  |
| `/app/configs`                    | GET    | admin — all configs                 |
| `/app/configs`                    | PATCH  | admin — bulk update                 |
| `/app/configs/{key}`              | PATCH  | admin — single update               |
| `/auth/register`                  | POST   | bootstrap-bypass on empty DB        |
| `/auth/login`                     | POST   | password only (no 2FA flow yet)     |
| `/auth/logout`                    | POST   | revokes jti + clears cookie         |
| `/auth/me`                        | GET    | auth-optional, returns user or null |
| `/auth/config`                    | GET    | passwordAuthEnabled flag            |
| `/users`                          | GET    | admin                               |
| `/users/{id}`                     | GET    | admin                               |
| `/users`                          | PUT    | update own profile                  |
| `/users/{id}`                     | DELETE | admin                               |
| `/users/{id}/activate`            | PATCH  | admin                               |
| `/users/{id}/deactivate`          | PATCH  | admin                               |

## Still to port (priority order)

1. **Per-route admin enforcement** — `RegisterAdmin` in `app`/`user`
   currently registers under the same huma API as public ones; the
   middleware chain doesn't run per-operation. Wrap the admin paths
   in a chi subrouter that applies `mw.RequireAdmin` before huma
   takes over. See the comment in `main.go` next to the admin
   registrations.
2. **Storage / S3 module** — `internal/storage` is empty. Port
   `apps/server/src/config/storage.config.ts` + the presigned-URL
   service. AWS SDK Go v2 imports are already in `go.mod`.
3. **File module** — uploads, downloads, multipart presigned URLs.
   The legacy file is `apps/server/src/modules/file/`.
4. **Folder module** — CRUD + tree navigation.
5. **Share module** — including the public alias endpoint, password
   gate, recipient notifications.
6. **Reverse-share module** — the biggest of the legacy modules (2800
   lines). Anonymous upload flow, alias, presigned URLs (matching the
   filename+extension API we already agreed on).
7. **2FA module** — TOTP setup, verify, backup codes. `pquerna/otp`
   already in `go.mod`.
8. **Auth providers (OIDC)** — `coreos/go-oidc` already in `go.mod`.
   The legacy backend has a 2200-line implementation; the Go version
   should be ~600 with the standard library doing most of the work.
9. **Email service** — `wneessen/go-mail` already in `go.mod`. Port
   `apps/server/src/modules/email`. SMTP settings still come from the
   `app_configs` table.
10. **Invite tokens** — small module, do last.
11. **Avatar upload** + **app logo** — image processing. The legacy
    backend uses sharp (libvips). For Go we'll bind libvips via
    `govips` once we want pixel-perfect parity; in the meantime a
    pure-Go `image` package implementation is fine.
12. **Embed routes** — `/embed/:id`, used by the share page for image
    previews.

## Build & run

You need Docker; Go isn't required on the host (the builder image has
it).

```sh
# Bring up Node backend + frontend + Traefik (default behaviour)
docker compose up -d

# Add the Go backend on the side, published on :3334
docker compose --profile go-backend up -d palmr-server-go

# Smoke-test
curl -sw "\n%{http_code}\n" http://localhost:3334/health
curl -sw "\n%{http_code}\n" http://localhost:3334/app/info
```

When the Go backend is feature-complete, swap the two by:

1. Deleting the `palmr-server` service block from `docker-compose.yaml`.
2. Renaming `palmr-server-go` → `palmr-server` and dropping the
   `profiles:` line.
3. Restarting Traefik (the dynamic config will pick the new container
   automatically since it routes by service name).

## Local development (host has Go ≥ 1.23 installed)

```sh
cd apps/server-go
make tidy            # generate go.sum
make run             # go run ./cmd/server
```

Set the same env vars the docker-compose passes (`JWT_SECRET`,
`DATA_DIR=./../server/.data`, etc.) — the binary reads the SQLite
file from `${DATA_DIR}/prisma/palmr.db`.

## Why these choices

| Concern        | Library                       | Why over alternatives                                                                  |
|----------------|-------------------------------|----------------------------------------------------------------------------------------|
| HTTP router    | `chi`                         | stdlib-compatible, minimal, mature                                                     |
| OpenAPI        | `huma/v2`                     | derives schema from Go types — closest analog to `fastify-type-provider-zod`           |
| ORM            | `sqlx` + plain SQL            | predictable; no schema duplication (Prisma owns the schema)                            |
| SQLite driver  | `modernc.org/sqlite`          | pure Go → no CGO → `FROM scratch` works                                                |
| JWT            | `golang-jwt/jwt/v5`           | same algorithm (HS256) and claim shape as the Node `jose` setup                        |
| OIDC           | `coreos/go-oidc/v3`           | battle-tested (Kubernetes, ArgoCD, Dex)                                                |
| S3             | `aws-sdk-go-v2`               | upstream AWS SDK, supports MinIO via custom endpoint                                   |
| TOTP           | `pquerna/otp`                 | matches what the Node backend uses (`speakeasy`)                                       |
| Mail           | `wneessen/go-mail`            | modern API, no implicit globals                                                        |
| QR             | `skip2/go-qrcode`             | pure Go, no native deps                                                                |
| Validation     | huma's struct tags            | enough for now — most legacy Zod refinements map to `min`/`max`/`required`/`format`    |
| Env            | `caarlos0/env/v11`            | struct-tagged, fails fast                                                              |

## Schema ownership

The DB schema is **owned by Prisma** in `apps/server/prisma/schema.prisma`.
The Go backend does NOT auto-migrate — it just opens the existing
`palmr.db` file. This way:

- The legacy Node entrypoint keeps running `prisma db push` and the
  pre-migration script.
- The Go backend never invents schema changes that diverge.
- Once the port is complete, schema management can be moved out of
  Prisma (e.g. to `pressly/goose` migrations) without touching the
  data.

## Open questions for later

- Replace huma with a hand-rolled router if startup ever becomes an
  issue. Huma's reflection-based schema generation is the only thing
  that runs at boot.
- The legacy backend uses CUID v1 IDs; Go inserts UUID v4. Both are
  strings and the DB doesn't care, but anyone joining via `id` in a
  raw query should know.
- The legacy jti revocation list is in-memory and single-instance. If
  Palmr ever scales horizontally, swap `auth.RevokeJTI` for a Redis or
  table-backed store.
