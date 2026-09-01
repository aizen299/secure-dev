-- 0005_findings: the canonical findings model.
--
-- Four tables, because a finding has four distinct lifetimes:
--
--   findings                identity, which never changes
--   finding_occurrences     where it was seen, per scan, which moves
--   finding_links           how it relates to others, which correlation adds to
--   finding_status_history  how its state changed, which is append-only
--
-- The split between the first two is the whole point of the fingerprint
-- strategy (docs/architecture/fingerprinting.md): a finding that moves down a
-- file is the same finding, so location lives on the occurrence and identity
-- does not contain it.

CREATE TYPE finding_status AS ENUM (
    'open',
    'acknowledged',
    'in_progress',
    'resolved',
    -- 'reopened' is distinct from 'open': a finding that came back is a
    -- different operational situation from one never fixed, and collapsing
    -- them loses the fact that a fix did not hold.
    'reopened',
    'false_positive',
    'ignored'
);

CREATE TYPE finding_severity AS ENUM (
    'critical', 'high', 'medium', 'low', 'info',
    -- 'unknown' is never guessed. "We do not know" and "it does not matter"
    -- are different claims and must not collapse into each other.
    'unknown'
);

CREATE TYPE finding_confidence AS ENUM ('high', 'medium', 'low');

CREATE TYPE finding_relationship AS ENUM (
    -- Exact duplicates are merged rather than linked, so they never appear
    -- here. The rest are links: §8 forbids merging findings for looking
    -- similar, so a relationship is a claim with a confidence attached.
    'likely_duplicate',
    'related'
);

CREATE TABLE findings (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    -- The stable identity across scans (§8). Scoped to the project: the same
    -- vulnerable dependency in two projects is two findings, because they are
    -- remediated, tracked, and risk-scored independently.
    fingerprint text NOT NULL,

    -- Which scanner reported it first. Deliberately NOT part of identity: the
    -- full set of reporters is derived from finding_occurrences, so a finding
    -- both grype and trivy report is one row with two occurrence sources.
    scanner            text NOT NULL,
    scanner_finding_id text,
    -- The scanner's own severity string, verbatim. Kept so a disagreement
    -- about a mapping is a question about the mapping and not a lost fact.
    scanner_severity   text,

    category    text NOT NULL,
    severity    finding_severity NOT NULL,
    confidence  finding_confidence NOT NULL,

    title       text NOT NULL,
    description text,
    remediation text,

    package         text,
    package_version text,
    purl            text,

    cve  text,
    cwe  text,
    cvss numeric(3,1),

    status     finding_status NOT NULL DEFAULT 'open',
    -- first_seen never moves. last_seen advances on every scan that still
    -- reports the finding, which is what makes "resolved" detectable: a
    -- finding whose last_seen is older than the project's latest scan was not
    -- reported by it.
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT findings_project_fingerprint_key UNIQUE (project_id, fingerprint),
    CONSTRAINT findings_fingerprint_is_sha256 CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT findings_title_not_blank CHECK (length(btrim(title)) > 0),
    CONSTRAINT findings_cvss_range CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    CONSTRAINT findings_seen_order CHECK (last_seen >= first_seen)
);

-- The lookup every scan performs: "have I seen this fingerprint before?".
-- Covered by the unique constraint above; this index serves the cross-project
-- question "where else does this appear?", which correlation (§9) needs.
CREATE INDEX findings_fingerprint_idx ON findings (fingerprint);
CREATE INDEX findings_project_status_idx ON findings (project_id, status);
CREATE INDEX findings_project_severity_idx ON findings (project_id, severity);
-- Partial: the overwhelming majority of queries are about findings that are
-- still a problem, and indexing resolved rows serves nothing.
CREATE INDEX findings_open_idx ON findings (project_id, severity)
    WHERE status IN ('open', 'reopened');
CREATE INDEX findings_cve_idx ON findings (cve) WHERE cve IS NOT NULL;

CREATE TABLE finding_occurrences (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    scan_id    uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- The reporting scanner, per sighting. Two scanners reporting one finding
    -- produce two occurrences, which is how independent agreement is recorded
    -- without duplicating the finding.
    scanner text NOT NULL,

    -- Where it was seen. This is the field the fingerprint deliberately
    -- excludes: a finding that moves down a file keeps its identity and gains
    -- an occurrence at the new line.
    file       text,
    start_line integer,
    end_line   integer,

    seen_at timestamptz NOT NULL DEFAULT now(),

    -- One sighting per finding, scan, scanner, and place. A scanner reporting
    -- the same finding twice at the same line in one scan is reporting it
    -- once.
    CONSTRAINT finding_occurrences_unique
        UNIQUE (finding_id, scan_id, scanner, file, start_line),
    CONSTRAINT finding_occurrences_lines_non_negative
        CHECK ((start_line IS NULL OR start_line >= 0) AND (end_line IS NULL OR end_line >= 0))
);

CREATE INDEX finding_occurrences_finding_id_idx ON finding_occurrences (finding_id);
CREATE INDEX finding_occurrences_scan_id_idx ON finding_occurrences (scan_id);

CREATE TABLE finding_links (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    from_finding_id uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    to_finding_id   uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,

    relationship finding_relationship NOT NULL,
    confidence   finding_confidence NOT NULL,
    -- Why the link was made, in a form a person can read. §9 requires
    -- correlation to be explainable; a relationship with no stated reason is
    -- an assertion rather than a finding about the code.
    evidence text NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT finding_links_unique UNIQUE (from_finding_id, to_finding_id, relationship),
    -- A finding is not related to itself, and a self-link would make every
    -- traversal cyclic for no benefit.
    CONSTRAINT finding_links_not_self CHECK (from_finding_id <> to_finding_id),
    CONSTRAINT finding_links_evidence_not_blank CHECK (length(btrim(evidence)) > 0)
);

CREATE INDEX finding_links_from_idx ON finding_links (from_finding_id);
CREATE INDEX finding_links_to_idx ON finding_links (to_finding_id);

-- Append-only, per §17: every lifecycle transition records who, when, why, and
-- both states.
--
-- This exists now rather than waiting for Phase 11's general audit_logs table
-- (T-24) because the history cannot be reconstructed later. A transition that
-- happens before the audit log exists is simply not recorded anywhere, and
-- "when did this become resolved, and why" would be unanswerable for that
-- period.
CREATE TABLE finding_status_history (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,

    from_status finding_status,
    to_status   finding_status NOT NULL,

    -- Who caused it. 'system' for scan-driven transitions, which is most of
    -- them: a finding becomes resolved because a scan stopped reporting it,
    -- not because a person decided anything. A named principal appears when
    -- Phase 11 adds identity and someone acknowledges or ignores a finding.
    actor text NOT NULL DEFAULT 'system',
    -- Why, in a fixed vocabulary rather than free text, so the reason is
    -- queryable: 'first_seen', 'still_present', 'not_reported', 'reopened'.
    reason text NOT NULL,
    -- The scan that caused it, when a scan did.
    scan_id uuid REFERENCES scans (id) ON DELETE SET NULL,

    changed_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT finding_status_history_actor_not_blank CHECK (length(btrim(actor)) > 0),
    CONSTRAINT finding_status_history_reason_not_blank CHECK (length(btrim(reason)) > 0),
    -- A transition from a state to itself is not a transition.
    CONSTRAINT finding_status_history_is_a_change CHECK (from_status IS NULL OR from_status <> to_status)
);

CREATE INDEX finding_status_history_finding_id_idx
    ON finding_status_history (finding_id, changed_at DESC);

CREATE TRIGGER findings_set_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
