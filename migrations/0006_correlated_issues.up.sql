-- 0006_correlated_issues: the contextual issue.
--
-- §9's worked example is precise about the shape of the answer it wants: three
-- findings from three scanners become ONE contextual issue, escalated, with all
-- three retained as evidence. Migration 0005 could express the "retained as
-- evidence" half through finding_links, but nothing in it could say "one
-- issue". A pairwise graph is not an issue; every consumer would have to
-- recompute connected components to answer "how many problems are there?", and
-- they would drift.
--
-- See docs/adr/017-correlation-issues-and-severity.md and
-- docs/architecture/correlation.md.

CREATE TABLE correlated_issues (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    -- What the members share, which is also the issue's identity. Kept as kind
    -- + value rather than one string so "every issue about this component" is
    -- an indexed lookup rather than a LIKE.
    --
    -- text with a CHECK rather than an enum: `image` and `endpoint` are already
    -- planned (they wait on Trivy image targets and ZAP, not on this schema),
    -- and widening a CHECK is an ordinary additive migration while ALTER TYPE
    -- ADD VALUE cannot be used in the same transaction that then references it.
    key_kind  text NOT NULL,
    key_value text NOT NULL,

    -- Derived: the worst member, possibly raised one step. A severity on the
    -- same scale as a finding's -- NOT a risk score. The 0-100 score is Phase
    -- 6's single pure function (§10), and it consumes this rather than
    -- competing with it.
    severity finding_severity NOT NULL,
    -- Whether the derivation raised it. Stored rather than recomputed so the
    -- escalation stays visible as a claim instead of being folded silently
    -- into the value.
    escalated boolean NOT NULL DEFAULT false,

    -- The distinct domains present, sorted. Two or more is what makes an issue
    -- cross-domain, which is the condition for escalating.
    categories text[] NOT NULL DEFAULT '{}',

    -- The issue in one sentence a person can read. §9 requires correlation to
    -- be explainable; an issue with no stated reason is an assertion.
    explanation text NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT correlated_issues_key_unique UNIQUE (project_id, key_kind, key_value),
    CONSTRAINT correlated_issues_kind_known CHECK (key_kind IN ('cve', 'purl', 'file')),
    CONSTRAINT correlated_issues_key_not_blank CHECK (length(btrim(key_value)) > 0),
    CONSTRAINT correlated_issues_explanation_not_blank CHECK (length(btrim(explanation)) > 0)
);

CREATE INDEX correlated_issues_project_severity_idx
    ON correlated_issues (project_id, severity);
CREATE INDEX correlated_issues_key_idx ON correlated_issues (key_kind, key_value);

-- Membership is an additional fact about a finding, never a replacement for
-- it. §9 requires a correlated group to keep its members individually
-- queryable, and §11 depends on it: each scanner's own remediation is the
-- authoritative account of how to fix its own finding, and a merge would
-- destroy all but one.
CREATE TABLE correlated_issue_members (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issue_id   uuid NOT NULL REFERENCES correlated_issues (id) ON DELETE CASCADE,
    finding_id uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,

    -- Why this finding is in this issue, in a form a person can read.
    evidence text NOT NULL,

    CONSTRAINT correlated_issue_members_unique UNIQUE (issue_id, finding_id),
    CONSTRAINT correlated_issue_members_evidence_not_blank
        CHECK (length(btrim(evidence)) > 0)
);

CREATE INDEX correlated_issue_members_issue_idx ON correlated_issue_members (issue_id);
-- "What issues is this finding part of?" -- the question the findings view asks.
CREATE INDEX correlated_issue_members_finding_idx ON correlated_issue_members (finding_id);

CREATE TRIGGER correlated_issues_set_updated_at
    BEFORE UPDATE ON correlated_issues
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
