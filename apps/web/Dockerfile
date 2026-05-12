# syntax=docker/dockerfile:1.6
#
# Palmr frontend (Next.js standalone) — single-service image.
#
# Build context: apps/web/ (NOT the repo root). Nothing outside this app
# is needed at build time, so we ship only this directory to the daemon.
# Talks to the backend over the docker network at API_BASE_URL (default
# http://palmr-server:3333 in the split compose).

FROM node:24-alpine AS base
RUN apk add --no-cache curl
RUN corepack enable pnpm
WORKDIR /app/web

# === deps stage ===
FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# === build stage ===
FROM base AS builder
COPY --from=deps /app/web/node_modules ./node_modules
COPY . ./
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
RUN pnpm run build

# === runtime stage ===
FROM node:24-alpine AS runner
RUN apk add --no-cache curl

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=5487
ENV HOSTNAME=0.0.0.0
# Default points to the backend service name in docker-compose. Override at
# runtime if the backend is reachable on a different host.
ENV API_BASE_URL=http://palmr-server:3333

ARG PALMR_UID=1001
ARG PALMR_GID=1001
RUN addgroup --system --gid ${PALMR_GID} nodejs \
 && adduser --system --uid ${PALMR_UID} --ingroup nodejs palmr

WORKDIR /app/web
COPY --from=builder --chown=palmr:nodejs /app/web/public ./public
COPY --from=builder --chown=palmr:nodejs /app/web/.next/standalone ./
COPY --from=builder --chown=palmr:nodejs /app/web/.next/static ./.next/static

USER palmr

EXPOSE 5487

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://127.0.0.1:5487/ >/dev/null || exit 1

CMD ["node", "server.js"]
