-- Scanner degradation reasons.
--
-- Replaces the single-purpose `truncated` boolean on scan_scanner_results with
-- an explainable set of reasons.
--
-- The boolean answered one question -- "was output cut off?" -- but the fact it
-- encoded is more general: this scanner ran, yet its coverage cannot be fully
-- trusted. Grype reports the build date of its vulnerability database, and a
-- scan against a stale database is a false clean: exit 0, fewer findings than
-- exist, no error anywhere. Trivy and ZAP have their own versions of the same
-- shape. Adding a second boolean per cause does not scale, and a bare
-- `degraded` status would not satisfy §12, which requires a gate to explain the
-- exact conditions that produced its result.
--
-- Deliberately NOT a CHECK against a fixed vocabulary. Adding a scanner must
-- require zero changes outside its own package (§7 rule 4), and a per-value
-- constraint would make every new adapter that reports a new reason also a
-- schema migration. The column is bounded and well-formed; the vocabulary is
-- owned by internal/scanners.

ALTER TABLE scan_scanner_results
    ADD COLUMN degradations text[] NOT NULL DEFAULT '{}';

-- Every truncated row already meant exactly this reason.
UPDATE scan_scanner_results
   SET degradations = ARRAY['output_truncated']
 WHERE truncated;

ALTER TABLE scan_scanner_results
    DROP COLUMN truncated;

ALTER TABLE scan_scanner_results
    -- Bounded like any other stored collection (§15.8). Sixteen is far above
    -- any plausible number of simultaneous reasons for one scanner.
    ADD CONSTRAINT scan_scanner_results_degradations_bounded
        CHECK (cardinality(degradations) <= 16),
    -- A NULL or empty element would read as "a reason exists but is unnamed",
    -- which is the unexplained degradation this migration exists to prevent.
    ADD CONSTRAINT scan_scanner_results_degradations_well_formed
        CHECK (array_position(degradations, NULL) IS NULL
               AND NOT (degradations && ARRAY['']::text[]));

COMMENT ON COLUMN scan_scanner_results.degradations IS
    'Reasons this scanner ran but its coverage is not fully trustworthy. '
    'Non-empty means the scan cannot be COMPLETED (§13).';
