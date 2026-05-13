-- Remove the vestigial `jwtSecret` row from app_configs. The Go runtime
-- reads the JWT secret from the JWT_SECRET environment variable, never
-- from the DB — but earlier seed runs inserted a placeholder row, which
-- then leaked into the admin settings UI as an editable field.
--
-- Existing deployments that already booted with the old seed need this
-- cleanup; new deployments never see the row (the seed entry has been
-- removed in lockstep).

-- +goose Up
DELETE FROM app_configs WHERE key = 'jwtSecret';

-- +goose Down
-- Intentional no-op — re-creating the row would reintroduce the leak we
-- just plugged. The runtime doesn't depend on it.
SELECT 1;
