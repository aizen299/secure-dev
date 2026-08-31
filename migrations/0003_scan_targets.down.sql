-- Rollback of 0003_scan_targets.
--
-- This drops the record of what each scan pointed at. Rolling back past 0003
-- with scans in the table therefore destroys audit data that cannot be
-- reconstructed. That is inherent to reversing an additive column, not an
-- oversight -- take a dump first (§17: security-relevant records are archived,
-- not silently discarded).

DROP INDEX IF EXISTS scans_target_idx;

ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_failure_reason_length,
    DROP CONSTRAINT IF EXISTS scans_requested_scanners_bounded,
    DROP CONSTRAINT IF EXISTS scans_target_size,
    DROP CONSTRAINT IF EXISTS scans_target_is_object;

ALTER TABLE scans
    DROP COLUMN IF EXISTS failure_reason,
    DROP COLUMN IF EXISTS requested_scanners,
    DROP COLUMN IF EXISTS target;
