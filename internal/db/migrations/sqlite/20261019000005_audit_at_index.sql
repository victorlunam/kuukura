-- migrate:up
-- Finds the chain tip (newest row) and serves the newest-first listing without sorting the table.
CREATE INDEX audit_log_at ON audit_log (at, id);

-- migrate:down
DROP INDEX audit_log_at;
