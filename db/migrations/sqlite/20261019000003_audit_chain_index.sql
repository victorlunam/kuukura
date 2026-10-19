-- migrate:up
-- Unique prev_hash keeps the audit hash chain linear (no forks).
CREATE UNIQUE INDEX audit_log_prev_hash ON audit_log (prev_hash);

-- migrate:down
DROP INDEX audit_log_prev_hash;
