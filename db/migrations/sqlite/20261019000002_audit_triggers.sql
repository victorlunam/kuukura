-- migrate:up
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is insert-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is insert-only'); END;

-- migrate:down
DROP TRIGGER audit_log_no_update;
DROP TRIGGER audit_log_no_delete;
