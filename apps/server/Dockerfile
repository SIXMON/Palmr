# =============================================================================
# Palmr Go backend — multi-stage build, final image is `FROM scratch`.
#
# Stages:
#   builder  — golang:1.23-alpine, downloads modules and produces a single
#              static binary (CGO_ENABLED=0).
#   tools    — alpine, only here to pull a current ca-certificates bundle
#              that we copy into scratch.
#   final    — FROM scratch, ~20 MB image: ca-certs + the static binary +
#              the seed JSON files. No shell, no libc, no package manager.
#
# Pure-Go dependencies make this possible:
#   - SQLite driver: modernc.org/sqlite (no CGO)
#   - everything else stdlib-friendly
# =============================================================================

# ----- stage 1: build the Go binary -----------------------------------------
FROM golang:1.23-alpine AS builder

# Build-time dependencies for `go mod download` (git fetches from VCS).
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

COPY go.mod go.sum ./

# First boot has no go.sum; tidy generates it. Cached after the first
# successful build (the module cache lives in /root/go/pkg/mod and is
# reused unless go.mod changes).
RUN go mod download

COPY . .

# Build flags:
#   -trimpath           — remove host paths from the binary for reproducibility
#   -ldflags "-s -w"    — strip symbols and DWARF, shaves ~30%
#   -tags netgo,osusergo — use the pure-Go resolvers (no /etc/nsswitch.conf
#                          required at runtime → works in scratch)
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags "-s -w -extldflags '-static'" \
      -tags 'netgo,osusergo' \
      -o /out/palmr-server \
      ./cmd/server

# ----- stage 2: collect a CA bundle, a passwd entry, and a prepared /data
# directory. `FROM scratch` has no shell, so we can't `mkdir` at boot —
# we ship the directory pre-owned by UID 1001 instead.
FROM alpine:3.20 AS tools
RUN apk add --no-cache ca-certificates
RUN echo "palmr:x:1001:1001::/data:/sbin/nologin" > /tmp/passwd
# Create /tmp/data/{prisma,uploads,temp-uploads} owned by 1001:1001 so the
# COPY into scratch carries those permissions. A fresh Docker named
# volume mounted at /data will inherit the 1001:1001 ownership on first
# mount (Docker copies the existing directory contents + perms into a
# brand-new volume), which is the only way to write inside a scratch
# image running as a non-root user.
RUN mkdir -p /tmp/data/prisma /tmp/data/uploads /tmp/data/temp-uploads \
    && chown -R 1001:1001 /tmp/data
# Stage a writable /tmp directory for the scratch image. The runtime
# needs one for multipart-upload spillover (ParseMultipartForm writes any
# bytes past its in-memory budget to os.TempDir(), which defaults to
# /tmp). A scratch image has no /tmp by default, so the avatar/logo
# upload would fail with "open /tmp/multipart-...: no such file or
# directory" the moment a body is larger than the in-RAM budget.
RUN mkdir -p /tmp/scratch-tmp && chown 1001:1001 /tmp/scratch-tmp && chmod 1777 /tmp/scratch-tmp

# ----- stage 3: final image, FROM scratch -----------------------------------
FROM scratch

COPY --from=tools  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=tools  /tmp/passwd                        /etc/passwd
COPY --from=tools  --chown=1001:1001 /tmp/data        /data
COPY --from=tools  --chown=1001:1001 /tmp/scratch-tmp /tmp
COPY --from=builder /out/palmr-server                 /palmr-server

# Seed JSON files (configs.json, providers.json) — the Go entrypoint copies
# them into /data/prisma on first boot if they aren't there yet.
COPY --from=builder /src/seed/                        /seed/

USER 1001:1001
WORKDIR /data
EXPOSE 3333

ENTRYPOINT ["/palmr-server"]
