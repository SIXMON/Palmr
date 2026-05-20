-- Track the last time a user did anything authenticated (any request that
-- carried a valid session cookie). Exposed in the admin user-management
-- table so operators can see who's actively using the app and prune dead
-- accounts.
--
-- The middleware bumps this column at most once per N minutes per user
-- (debounce lives in cmd/server/main.go) so a chatty client can't hammer
-- the row on every API call.
--
-- Nullable on purpose: existing rows have no history before this
-- migration shipped, and we surface NULL as "—" in the UI rather than
-- back-filling with createdAt (which would be misleading).

-- +goose Up
ALTER TABLE users ADD COLUMN "lastSeenAt" DATETIME;

-- +goose Down
-- SQLite supports DROP COLUMN since 3.35 (2021). modernc.org/sqlite is
-- well past that, but anyone hand-rolling a downgrade on an older
-- engine can comment this out.
ALTER TABLE users DROP COLUMN "lastSeenAt";
