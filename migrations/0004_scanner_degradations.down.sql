-- Rollback of 0004_scanner_degradations.
--
-- Lossy, and not symmetrically so. `truncated` is restored from the
-- output_truncated reason, but every other reason -- a stale vulnerability
-- database, a partial ruleset -- has no boolean to be restored into and is
-- discarded. Rolling back past 0004 therefore converts explained degraded
-- coverage into apparently complete coverage, which is the exact false
-- reassurance the forward migration exists to prevent. Take a dump first
-- (§17: security-relevant records are archived, not silently discarded).

ALTER TABLE scan_scanner_results
    ADD COLUMN truncated boolean NOT NULL DEFAULT false;

UPDATE scan_scanner_results
   SET truncated = true
 WHERE degradations && ARRAY['output_truncated'];

ALTER TABLE scan_scanner_results
    DROP CONSTRAINT IF EXISTS scan_scanner_results_degradations_well_formed,
    DROP CONSTRAINT IF EXISTS scan_scanner_results_degradations_bounded;

ALTER TABLE scan_scanner_results
    DROP COLUMN IF EXISTS degradations;
