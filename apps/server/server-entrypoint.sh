#!/bin/sh
# Entrypoint for the split Palmr backend container.
#
# Differences from the legacy monolithic start script:
#   - no MinIO bootstrap (object storage lives in its own container)
#   - no supervisord (single-process container)
#   - no recursive chown on every boot (the data volume should be set up once;
#     we only chown the directories we'll definitely touch)
#
# Data layout under /data (bind-mount/volume target):
#   /data/prisma          SQLite db + JSON config
#   /data/uploads         (only used when ENABLE_S3=false, otherwise unused)
#   /data/temp-uploads
set -e

TARGET_UID=${PALMR_UID:-1001}
TARGET_GID=${PALMR_GID:-1001}

echo "🚀 Starting Palmr backend (split container)"
echo "   UID/GID: $TARGET_UID:$TARGET_GID"
echo "   Storage: ${ENABLE_S3:-false} (external S3 = true)"

mkdir -p /data/prisma /data/uploads /data/temp-uploads

if [ "$(id -u)" = "0" ]; then
  # Cheap shallow chown so the running user owns the directory entries we
  # write into. Files placed there inherit ownership via the directory.
  chown "$TARGET_UID:$TARGET_GID" /data /data/prisma /data/uploads /data/temp-uploads 2>/dev/null || true
fi

run_as_user() {
  if [ "$(id -u)" = "0" ]; then
    su-exec "$TARGET_UID:$TARGET_GID" "$@"
  else
    "$@"
  fi
}

# Seed support files (configs.json / providers.json / check-missing.js) ship
# inside the image under /app/server/prisma. Copy them into /data on first
# boot so admins can tweak them in the volume without rebuilding the image.
if [ ! -f /data/prisma/configs.json ]; then
  echo "📄 Installing default config files into /data/prisma"
  cp -f /app/server/prisma/configs.json /data/prisma/configs.json 2>/dev/null || true
  cp -f /app/server/prisma/providers.json /data/prisma/providers.json 2>/dev/null || true
  cp -f /app/server/prisma/check-missing.js /data/prisma/check-missing.js 2>/dev/null || true
  if [ "$(id -u)" = "0" ]; then
    chown "$TARGET_UID:$TARGET_GID" /data/prisma/configs.json /data/prisma/providers.json /data/prisma/check-missing.js 2>/dev/null || true
  fi
fi

cd /app/server

if [ ! -f /data/prisma/palmr.db ]; then
  echo "🗄️  First run: creating database schema and seeding"
  run_as_user npx prisma db push --schema=./prisma/schema.prisma --skip-generate
  run_as_user node ./prisma/seed.js
else
  echo "♻️  Existing database — applying schema changes"

  # Cleanup orphan rows that would block the NOT NULL migration introduced
  # by the security audit (Share.creatorId went from optional+SetNull to
  # required+Cascade). The script is idempotent and a no-op on fresh DBs.
  run_as_user node ./prisma/pre-migrate.js

  run_as_user npx prisma db push --schema=./prisma/schema.prisma --skip-generate --accept-data-loss

  if [ -f /data/prisma/check-missing.js ]; then
    NEEDS_SEEDING=$(run_as_user node /data/prisma/check-missing.js check-seeding 2>/dev/null || echo "true")
    if [ "$NEEDS_SEEDING" = "true" ]; then
      echo "🌱 Seeding missing rows"
      run_as_user node ./prisma/seed.js
    fi
  fi
fi

echo "✅ Backend ready, starting Fastify on :$PORT"

if [ "$(id -u)" = "0" ]; then
  exec su-exec "$TARGET_UID:$TARGET_GID" node dist/server.js
else
  exec node dist/server.js
fi
