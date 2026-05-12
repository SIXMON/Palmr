# syntax=docker/dockerfile:1.6
#
# Palmr backend (Fastify) — single-service image.
#
# Build context: apps/server/ (NOT the repo root). Everything this image
# needs lives under apps/server/, so the build sends only this app to the
# Docker daemon — much faster and smaller than shipping the whole monorepo.
# Seed support files (configs.json, providers.json, check-missing.js) live
# under prisma/ alongside schema.prisma so they travel with the app.
#
# This container does NOT bundle MinIO, supervisord, or the web frontend —
# they each run in their own service. The legacy monolithic Dockerfile at
# the repo root is still available if you want everything in one image.

FROM node:24-alpine AS base
RUN apk add --no-cache curl openssl su-exec
RUN corepack enable pnpm
WORKDIR /app/server

# === deps stage ===
FROM base AS deps
COPY package*.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# === build stage ===
FROM base AS builder
COPY --from=deps /app/server/node_modules ./node_modules
COPY . ./
RUN npx prisma generate
RUN pnpm build

# === runtime stage ===
FROM base AS runner

ENV NODE_ENV=production
ENV PORT=3333

# UID/GID stay configurable so bind-mounted volumes can match host ownership.
ARG PALMR_UID=1001
ARG PALMR_GID=1001
RUN addgroup --system --gid ${PALMR_GID} nodejs \
 && adduser --system --uid ${PALMR_UID} --ingroup nodejs palmr

# /data is the bind-mount target for SQLite + (optional) filesystem uploads.
RUN mkdir -p /data/prisma /data/uploads /data/temp-uploads /home/palmr \
 && chown -R palmr:nodejs /data /home/palmr

# Copy compiled app (prisma/ already carries configs.json, providers.json,
# check-missing.js so we don't need a separate COPY for them).
COPY --from=builder --chown=palmr:nodejs /app/server/dist ./dist
COPY --from=builder --chown=palmr:nodejs /app/server/node_modules ./node_modules
COPY --from=builder --chown=palmr:nodejs /app/server/prisma ./prisma
COPY --from=builder --chown=palmr:nodejs /app/server/package.json ./

COPY --chown=palmr:nodejs server-entrypoint.sh /app/server-entrypoint.sh
RUN chmod +x /app/server-entrypoint.sh

# Persistent state (SQLite + uploads + temp-uploads) lives under /data so it
# survives container recreation. The runtime image's /app/server is the read-
# only application bundle, not the data directory.
ENV DATA_DIR=/data
ENV DATABASE_URL="file:/data/prisma/palmr.db"

EXPOSE 3333

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -sf http://127.0.0.1:3333/health >/dev/null || exit 1

ENTRYPOINT ["/app/server-entrypoint.sh"]
