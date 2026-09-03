-- Rollback of 0015_audit_history_not_relation.
--
-- Restoring the foreign key restores the deadlock it caused: projects with
-- audit history become undeletable again, failing with an error about a table
-- the operator did not touch.
--
-- It can also fail outright. Any audit row whose project has been deleted
-- since 0015 applied now holds an id with no matching project, and re-adding
-- the constraint rejects exactly those rows. That is not a flaw in this
-- rollback: it is the constraint correctly reporting that the data no longer
-- fits the shape it describes. Clear or null those rows first if you must go
-- back -- which requires disabling the append-only trigger, and is itself a
-- decision worth making deliberately rather than as part of a migration.

DROP INDEX IF EXISTS audit_logs_project_id_idx;

ALTER TABLE audit_logs
    DROP CONSTRAINT IF EXISTS audit_logs_project_slug_not_blank;

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS project_slug;

ALTER TABLE audit_logs
    ADD CONSTRAINT audit_logs_project_id_fkey
        FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE SET NULL;
