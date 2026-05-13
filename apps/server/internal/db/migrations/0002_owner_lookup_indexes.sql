-- Indexes for owner-scoped lookups that the Go backend runs on every
-- "list mine" / dashboard page. Prisma's schema.prisma declared these
-- columns as foreign keys but SQLite (unlike PostgreSQL) does not
-- auto-index FKs, so the original schema scanned the full table every
-- time a user opened their files / shares / reverse-shares list.
--
-- All five tables typically have <100k rows in a single tenant, so the
-- impact is small at first — but it grows linearly with usage and is
-- effectively free to fix.

-- +goose Up
CREATE INDEX IF NOT EXISTS "files_userId_idx"                     ON "files"("userId");
CREATE INDEX IF NOT EXISTS "shares_creatorId_idx"                 ON "shares"("creatorId");
CREATE INDEX IF NOT EXISTS "reverse_shares_creatorId_idx"         ON "reverse_shares"("creatorId");
CREATE INDEX IF NOT EXISTS "share_recipients_shareId_idx"         ON "share_recipients"("shareId");
CREATE INDEX IF NOT EXISTS "reverse_share_files_reverseShareId_idx" ON "reverse_share_files"("reverseShareId");

-- +goose Down
DROP INDEX IF EXISTS "files_userId_idx";
DROP INDEX IF EXISTS "shares_creatorId_idx";
DROP INDEX IF EXISTS "reverse_shares_creatorId_idx";
DROP INDEX IF EXISTS "share_recipients_shareId_idx";
DROP INDEX IF EXISTS "reverse_share_files_reverseShareId_idx";
