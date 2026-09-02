-- Rollback of 0011_audit_logs.
--
-- This deletes the audit trail. That is a materially different act from the
-- other rollbacks in this directory: findings can be re-scanned and scores
-- recomputed, but the record of who changed a security policy and what it was
-- before exists nowhere else.
--
-- The table is append-only precisely so that its contents cannot be quietly
-- removed; running this removes them all at once instead. Export before
-- running it, and treat having run it as an event worth explaining.

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs;
DROP FUNCTION IF EXISTS audit_logs_are_append_only();

DROP INDEX IF EXISTS audit_logs_occurred_idx;
DROP INDEX IF EXISTS audit_logs_project_idx;
DROP INDEX IF EXISTS audit_logs_resource_idx;
DROP TABLE IF EXISTS audit_logs;
