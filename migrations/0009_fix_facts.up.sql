-- 0009_fix_facts: what to do about a finding, from the vendor rather than us.
--
-- §11 makes deterministic scanner and vendor data the authoritative source of
-- truth for remediation. Grype has reported `fix.versions` and `fix.state` on
-- every match since Phase 3b and the parser discarded both, so the single most
-- actionable fact the platform can obtain has never been stored.
--
-- See docs/adr/020-remediation-actions-and-prioritization.md.

-- Four states, not a boolean. "No fix yet", "there will never be one", and
-- "nobody told us" lead to three different decisions, and collapsing them is
-- how a platform ends up recommending an upgrade to a version that does not
-- exist. NULL is the fourth state: unknown.
CREATE TYPE finding_fix_state AS ENUM ('fixed', 'not-fixed', 'wont-fix');

ALTER TABLE findings
    ADD COLUMN fix_state finding_fix_state,
    -- Versions reported to resolve this, verbatim and unordered. SecureOps
    -- does not choose between them: picking one needs ecosystem-specific
    -- version ordering, and a comparator correct for semver is wrong for
    -- PEP 440 or Debian epochs.
    ADD COLUMN fix_versions text[] NOT NULL DEFAULT '{}',
    -- Advisory and documentation links. References are where to read about a
    -- finding, not what to do about it.
    ADD COLUMN fix_references text[] NOT NULL DEFAULT '{}';

ALTER TABLE findings
    -- The contradiction the Go model also rejects: a state saying no fix
    -- exists cannot carry the version that fixes it. Stored, it would surface
    -- as an upgrade recommendation for something unfixable.
    ADD CONSTRAINT findings_fix_versions_need_a_fix CHECK (
        cardinality(fix_versions) = 0 OR fix_state = 'fixed'),
    -- A 'fixed' state naming no version cannot be acted on, so it is not a
    -- state worth storing: the adapter degrades it to unknown before it
    -- reaches here, and this makes that a schema-level guarantee.
    ADD CONSTRAINT findings_fixed_state_names_a_version CHECK (
        fix_state IS DISTINCT FROM 'fixed' OR cardinality(fix_versions) > 0);

-- Supports the remediation engine's first question: which of this project's
-- findings actually have somewhere to upgrade to?
CREATE INDEX findings_fix_state_idx
    ON findings (project_id, fix_state)
    WHERE fix_state IS NOT NULL;
