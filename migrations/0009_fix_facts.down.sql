-- Rollback of 0009_fix_facts.
--
-- Safe to lose: fix facts are re-read from scanner output on the next scan, and
-- they are a snapshot of advisory data that changes upstream anyway. What is
-- not recovered is the record of what was known to be fixable at the time a
-- remediation decision was made or deferred.

DROP INDEX IF EXISTS findings_fix_state_idx;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_fix_versions_need_a_fix,
    DROP CONSTRAINT IF EXISTS findings_fixed_state_names_a_version;

ALTER TABLE findings
    DROP COLUMN IF EXISTS fix_state,
    DROP COLUMN IF EXISTS fix_versions,
    DROP COLUMN IF EXISTS fix_references;

DROP TYPE IF EXISTS finding_fix_state;
