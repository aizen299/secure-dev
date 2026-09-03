-- 0015_audit_history_not_relation: let a project be deleted.
--
-- 0011 introduced two controls that contradict each other. Line 30 declared
--   project_id uuid REFERENCES projects (id) ON DELETE SET NULL
-- and lines 64-70 installed triggers refusing EVERY update and delete on the
-- table. The cascade the foreign key requires is exactly the statement the
-- trigger forbids, so deleting a project fails the moment one audit row
-- references it -- with an error naming neither the project nor the cause.
--
-- Since ADR 022 the API writes an audit record when a project is created, so
-- in practice every project a deployment has ever created is undeletable.
--
-- The fix is to stop asserting a relation that was never true. An audit log
-- records what happened; a foreign key claims the subject still exists, which
-- is a statement about present state and the one thing this table is not
-- about. See ADR 028.

ALTER TABLE audit_logs
    -- resource_id has always been an unconstrained identifier: a deleted
    -- finding's id dangles there and nothing breaks. project_id now holds the
    -- same contract, which is what it should have had from the start.
    DROP CONSTRAINT IF EXISTS audit_logs_project_id_fkey,

    -- An id alone degrades badly once its project is gone: `project
    -- 38150c6b-...` proves something happened and says nothing about what.
    -- The slug keeps the record legible to an investigation.
    --
    -- Nullable, because entries predating this migration have no slug to
    -- backfill -- their projects may already be gone -- and inventing one
    -- would be writing a fact into an audit table that nobody observed.
    ADD COLUMN project_slug text,

    ADD CONSTRAINT audit_logs_project_slug_not_blank CHECK (
        project_slug IS NULL OR length(btrim(project_slug)) > 0);

-- Serves "everything that has happened to this project", which is the question
-- an investigation opens with, and which no longer has a foreign key to
-- traverse (§17).
CREATE INDEX IF NOT EXISTS audit_logs_project_id_idx
    ON audit_logs (project_id, occurred_at DESC)
    WHERE project_id IS NOT NULL;
