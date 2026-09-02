-- 0010_security_policies: the gate configuration, and the decisions it made.
--
-- §12 requires per-project policy that is data rather than hardcoded
-- thresholds, and §17 names both tables. See
-- docs/adr/021-policy-evaluation-and-gates.md.

CREATE TYPE policy_level AS ENUM ('warn', 'fail');

-- 'pass' is deliberately absent from this enum. §12 and §13 both forbid
-- reading a partial scan as a complete one, and the failure is specific: a
-- scanner that crashes reports nothing, fewer findings breach fewer rules, and
-- a broken scan would pass *because* it broke. Making 'pass' unrepresentable
-- means no configuration can reintroduce that.
CREATE TABLE security_policies (
    project_id uuid PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,

    -- Rules as JSON rather than a row per rule. The rule vocabulary is
    -- kind + selector + threshold + level, and it is read and written whole:
    -- a policy is evaluated in one piece, and a partially-applied policy is
    -- not a state worth being able to represent.
    rules jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- How to treat a scan that did not complete. Never 'pass'.
    incomplete_scan policy_level NOT NULL DEFAULT 'warn',

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT security_policies_rules_is_array CHECK (jsonb_typeof(rules) = 'array')
);

CREATE TRIGGER security_policies_set_updated_at
    BEFORE UPDATE ON security_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TYPE policy_verdict AS ENUM ('pass', 'warn', 'fail');

-- One decision per scan. A gate outcome is a statement about a moment: the
-- policy in force is captured here alongside it, so editing the policy later
-- cannot rewrite what was decided.
CREATE TABLE policy_results (
    scan_id    uuid PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    verdict policy_verdict NOT NULL,

    -- Every rule evaluated, breached or not, with its threshold and the
    -- observed value. §12 forbids a bare verdict, and a stored verdict with no
    -- conditions is exactly that -- unreproducible six months later.
    conditions jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- The policy that produced this verdict, verbatim.
    evaluated_policy jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Whether the scan had full scanner coverage, and whether that changed the
    -- verdict. A WARN caused by a crashed scanner and one caused by a breached
    -- rule need different responses.
    scan_complete      boolean NOT NULL,
    coverage_downgrade boolean NOT NULL DEFAULT false,

    summary text NOT NULL,
    evaluated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT policy_results_conditions_is_array CHECK (jsonb_typeof(conditions) = 'array'),
    -- The invariant the whole coverage rule exists for, stated where no code
    -- path can route around it.
    CONSTRAINT policy_results_incomplete_never_passes CHECK (
        scan_complete OR verdict <> 'pass')
);

CREATE INDEX policy_results_project_evaluated_idx
    ON policy_results (project_id, evaluated_at DESC);
