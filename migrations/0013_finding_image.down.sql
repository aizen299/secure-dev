-- Rollback of 0013_finding_image.
--
-- Safe in a way most of these rollbacks are not: the column is derived from the
-- fingerprint rather than the source of it, so dropping it loses a query path
-- and no identity. Container findings keep their fingerprints, their lifecycle,
-- and their history; they merely stop being filterable by image until the
-- migration is reapplied, at which point the next scan repopulates the column.

DROP INDEX IF EXISTS findings_project_image_idx;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_image_not_blank,
    DROP CONSTRAINT IF EXISTS findings_image_length;

ALTER TABLE findings
    DROP COLUMN IF EXISTS image;
