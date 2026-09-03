-- Rollback of 0014_finding_endpoint.
--
-- Safe in the same way 0013's rollback is: the column is derived from the
-- fingerprint rather than the source of it, so dropping it loses a query path
-- and no identity. DAST findings keep their fingerprints, their lifecycle, and
-- their history; they stop being filterable by endpoint until the migration is
-- reapplied, at which point the next scan repopulates the column.

DROP INDEX IF EXISTS findings_project_endpoint_idx;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_endpoint_not_blank,
    DROP CONSTRAINT IF EXISTS findings_endpoint_length;

ALTER TABLE findings
    DROP COLUMN IF EXISTS endpoint;
