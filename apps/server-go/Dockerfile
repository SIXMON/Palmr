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

COPY . .

# First boot has no go.sum; tidy generates it. Cached after the first
# successful build (the module cache lives in /root/go/pkg/mod and is
# reused unless go.mod changes).
RUN go mod tidy

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

# ----- stage 2: collect a CA bundle and a passwd entry ----------------------
# `FROM scratch` has no /etc/passwd. We mint a single-line one here so the
# binary can run as a non-root UID and Go's user.Current() still works.
FROM alpine:3.20 AS tools
RUN apk add --no-cache ca-certificates
RUN echo "palmr:x:1001:1001::/data:/sbin/nologin" > /tmp/passwd

# ----- stage 3: final image, FROM scratch -----------------------------------
FROM scratch

COPY --from=tools  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=tools  /tmp/passwd                        /etc/passwd
COPY --from=builder /out/palmr-server                 /palmr-server

# Seed JSON files (configs.json, providers.json) — the Go entrypoint copies
# them into /data/prisma on first boot if they aren't there yet.
COPY --from=builder /src/seed/                        /seed/

USER 1001:1001
WORKDIR /data
EXPOSE 3333

ENTRYPOINT ["/palmr-server"]
