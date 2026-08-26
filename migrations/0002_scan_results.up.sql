-- 0002_scan_results: per-scanner outcomes and raw scanner output.
--
-- Phase 2 needs two things the scans table cannot express well:
--   1. Per-scanner status, so a PARTIAL scan says which scanner degraded it
--      and why (CLAUDE.md §13). This is a queryable table rather than jsonb
--      because "which scanners are failing across the fleet?" is a real
--      operational question.
--   2. Raw scanner output, stored verbatim and size-capped, so results can be
--      re-parsed when normalization improves (§8).

CREATE TYPE scanner_result_status AS ENUM (
    'pending',
    'running',
    'succeeded',
    'failed',
    -- 'skipped' means the scanner never ran, usually because its binary is
    -- absent. Absent coverage and broken coverage need different responses.
    'skipped'
);

CREATE TABLE scan_scanner_results (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scanner     text NOT NULL,
    status      scanner_result_status NOT NULL DEFAULT 'pending',
    -- The scanner binary version. Results are only reproducible relative to
    -- it, so it is captured per scan (§7 rule 6).
    scanner_version text,
    exit_code   integer,
    duration_ms bigint,
    -- A fixed, non-sensitive summary. Raw stderr is deliberately NOT stored:
    -- it can contain repository content and detected secret values (§15.3).
    error       text,
    -- Output hit the size cap, so this result is incomplete and must never be
    -- normalized as though it were whole.
    truncated   boolean NOT NULL DEFAULT false,
    started_at  timestamptz,
    finished_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One row per scanner per scan; a retry updates in place.
    CONSTRAINT scan_scanner_results_scan_scanner_key UNIQUE (scan_id, scanner),
    CONSTRAINT scan_scanner_results_scanner_not_blank CHECK (length(btrim(scanner)) > 0),
    CONSTRAINT scan_scanner_results_duration_non_negative CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT scan_scanner_results_finished_after_started CHECK (
        finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at
    )
);

CREATE INDEX scan_scanner_results_scan_id_idx ON scan_scanner_results (scan_id);
-- Supports "which scanners are failing, and where?" across projects.
CREATE INDEX scan_scanner_results_scanner_status_idx ON scan_scanner_results (scanner, status);

CREATE TABLE scan_raw_results (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scanner       text NOT NULL,
    scanner_version text,
    -- Verbatim scanner output. bytea rather than jsonb on purpose: the bytes
    -- are stored exactly as produced, including output that is not valid JSON,
    -- so a malformed result can still be examined after the fact.
    output        bytea NOT NULL,
    output_bytes  bigint NOT NULL,
    truncated     boolean NOT NULL DEFAULT false,
    collected_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_raw_results_scan_scanner_key UNIQUE (scan_id, scanner),
    CONSTRAINT scan_raw_results_size_non_negative CHECK (output_bytes >= 0)
);

CREATE INDEX scan_raw_results_scan_id_idx ON scan_raw_results (scan_id);

CREATE TRIGGER scan_scanner_results_set_updated_at
    BEFORE UPDATE ON scan_scanner_results
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
