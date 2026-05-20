# syntax=docker/dockerfile:1.6
#
# Palmr frontend — static export served by nginx.
#
# Pipeline:
#   builder (Bun)  → `bun install` + `next build`. With output:"export" in
#                    next.config.ts this produces a flat `out/` tree of
#                    HTML/CSS/JS — no Node runtime required afterwards.
#   runtime (nginx) → nginx:alpine serves /usr/share/nginx/html and
#                    proxies /api/*, /e/{id}, /s/*, /r/* to the Go backend
#                    via the rules in nginx.conf. The Go backend handles
#                    OG-tag rendering for crawler UAs (see /og/s, /og/r).
#
# Build context: apps/web/. The Dockerfile reads bun.lock + package.json
# first so the deps layer caches across source edits.

# === build stage =============================================================
FROM oven/bun:1-alpine AS builder

WORKDIR /app/web

# Cache the dep install layer separately — package.json/bun.lock changes
# bust it; everything else doesn't.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . ./

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
# `next build` with output:"export" writes a static site to ./out
RUN bun run build

# === runtime stage ===========================================================
FROM nginx:1.27-alpine AS runner

# curl for the healthcheck; the rest of nginx:alpine is already what we need.
RUN apk add --no-cache curl

# Backend coordinates. Defaults match docker-compose service DNS; override
# at runtime if the backend is reachable on a different host/port.
ENV BACKEND_HOST=palmr-server
ENV BACKEND_PORT=3333

# The compose stack listens on this; matches the previous Next.js standalone
# port so existing reverse-proxy rules keep working.
EXPOSE 5487

# nginx.conf is a template — BACKEND_HOST/BACKEND_PORT get expanded by
# nginx's built-in envsubst pass at container start. /docker-entrypoint.d
# scripts run in the official image before nginx starts.
COPY nginx.conf /etc/nginx/templates/default.conf.template

# Static site. Owned by `nginx` UID 101 (the image's pre-baked nginx
# user) so the worker processes can read it without root.
# `--chmod=0555` (r-x for everyone) keeps directories traversable and
# files readable while removing write bits — nginx never writes here,
# everything under html/ is immutable for the lifetime of the image
# (sonar docker:S6504).
COPY --from=builder --chown=nginx:nginx --chmod=0555 /app/web/out /usr/share/nginx/html

# Healthcheck hits the dedicated /health endpoint declared in nginx.conf.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -sf http://127.0.0.1:5487/health >/dev/null || exit 1

# The default nginx:alpine entrypoint takes care of envsubst on the
# templates directory and then `exec nginx -g 'daemon off;'`.
