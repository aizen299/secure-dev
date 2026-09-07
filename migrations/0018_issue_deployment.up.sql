-- 0018_issue_deployment: whether an issue's package reached the built artifact.
--
-- Evidence, not a judgement. It moves no severity and no risk score
-- (docs/adr/037-deployment-evidence-from-the-sbom.md): the useful direction is
-- downward, and lowering a real vulnerability's standing because an inventory
-- did not mention its package would turn every way that inventory can be wrong
-- into a way to under-report.

-- 'unknown' is the DEFAULT and a first-class value, not a gap awaiting data.
--
-- Most projects have no image scan, so most issues will carry it forever. A
-- state that quietly meant "probably fine" would be the same failure as an EPSS
-- probability defaulting to zero (ADR 018): absence of evidence rendered as
-- evidence of absence.
CREATE TYPE issue_deployment AS ENUM ('unknown', 'deployed', 'not_deployed');

ALTER TABLE correlated_issues
    ADD COLUMN deployment issue_deployment NOT NULL DEFAULT 'unknown',

    -- The prose a person reads, naming the image scan and its date. Empty when
    -- the state is unknown: there is nothing to say, and inventing a sentence
    -- for it would imply a comparison nobody made.
    ADD COLUMN deployment_evidence text NOT NULL DEFAULT '',

    -- Which artifact the comparison was against. NOT a foreign key to scans:
    -- an issue's evidence must survive the deletion of the scan it cites, the
    -- same reasoning ADR 028 applies to audit references. A dangling id here
    -- is a historical fact, not a broken pointer.
    ADD COLUMN artifact_scan_id uuid;

ALTER TABLE correlated_issues
    ADD CONSTRAINT correlated_issues_deployment_evidence_bounded
        CHECK (length(deployment_evidence) <= 512),

    -- An unknown state has nothing to cite. Enforced rather than trusted,
    -- because a stale scan id beside 'unknown' would read as a comparison that
    -- was made and lost.
    ADD CONSTRAINT correlated_issues_unknown_cites_nothing
        CHECK (deployment <> 'unknown' OR (artifact_scan_id IS NULL AND deployment_evidence = ''));

-- "Which issues are declared but not deployed" is the query this exists to
-- serve, and the one a person triaging asks. Partial, because the rows that
-- answer it are a small minority of a table that grows with every project.
CREATE INDEX correlated_issues_not_deployed_idx
    ON correlated_issues (project_id)
    WHERE deployment = 'not_deployed';
