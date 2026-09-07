-- Rollback of 0018_issue_deployment.
--
-- Loses deployment evidence and nothing else. Safe: the evidence is derived
-- entirely from stored components and is recomputed on every correlation run,
-- so reapplying the migration and rescanning reproduces it. Issues keep their
-- identity, members, severity and explanation -- none of which this column ever
-- influenced, by design.

DROP INDEX IF EXISTS correlated_issues_not_deployed_idx;

ALTER TABLE correlated_issues
    DROP CONSTRAINT IF EXISTS correlated_issues_unknown_cites_nothing,
    DROP CONSTRAINT IF EXISTS correlated_issues_deployment_evidence_bounded;

ALTER TABLE correlated_issues
    DROP COLUMN IF EXISTS artifact_scan_id,
    DROP COLUMN IF EXISTS deployment_evidence,
    DROP COLUMN IF EXISTS deployment;

DROP TYPE IF EXISTS issue_deployment;
