-- 0003_scan_targets: record what a scan pointed at, and why it failed.
--
-- Phase 3 introduces POST /api/v1/scans, the first way a scan is created
-- outside a test. Three facts the scans table cannot currently hold become
-- necessary the moment a client can submit one:
--
--   1. target -- what was actually scanned. Without it a scan record is not
--      reproducible and not auditable: "this scan found nothing" is meaningless
--      if nobody can say what it looked at (CLAUDE.md §13, scans are durable
--      entities).
--   2. requested_scanners -- the explicit selection, if any. An empty array
--      means "every scanner that supports this target kind", resolved by the
--      registry at execution time. Storing the request separately from the
--      per-scanner results in scan_scanner_results keeps "what was asked for"
--      distinguishable from "what ran".
--   3. failure_reason -- why a scan failed before any scanner produced a
--      result. Until now such a scan finalized as FAILED with no explanation
--      anywhere. A gate result a user cannot explain is a gate result a user
--      will route around (§12).
--
-- All three changes are additive: new nullable or defaulted columns, no
-- rewrite of existing rows, no change to any existing constraint (§24).

ALTER TABLE scans
    -- The validated scanners.Target, stored as submitted-and-normalized. It is
    -- plain data by construction: the target model carries no commands and no
    -- scripts, precisely so that a queue payload cannot become an execution
    -- payload (§14.4).
    ADD COLUMN target jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Adapter names only. Never arguments, never flags: an argument vector
    -- assembled from stored client input is the shell-injection hole this
    -- schema must not make available (§25.11).
    ADD COLUMN requested_scanners text[] NOT NULL DEFAULT '{}',

    -- A fixed, non-sensitive summary chosen from a closed set in the worker.
    -- Never a raw error: those quote repository content and can contain a
    -- detected secret (§15.3).
    ADD COLUMN failure_reason text;

ALTER TABLE scans
    ADD CONSTRAINT scans_target_is_object CHECK (jsonb_typeof(target) = 'object'),
    -- Bounded like every other external input (§15.8). The cap is generous
    -- relative to a legitimate target and small enough that a client cannot
    -- use the scans table as storage.
    ADD CONSTRAINT scans_target_size CHECK (pg_column_size(target) <= 8192),
    ADD CONSTRAINT scans_requested_scanners_bounded CHECK (
        cardinality(requested_scanners) <= 32
    ),
    ADD CONSTRAINT scans_failure_reason_length CHECK (
        failure_reason IS NULL OR length(failure_reason) <= 512
    );

-- Supports "show me this project's scans of that repository", the query the
-- dashboard's scan history runs. jsonb_path_ops is the smaller, faster index
-- for the containment operator, which is the only way this column is queried.
CREATE INDEX scans_target_idx ON scans USING gin (target jsonb_path_ops);
