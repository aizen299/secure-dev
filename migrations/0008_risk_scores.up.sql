-- 0008_risk_scores: the project score, per scan, with its provenance.
--
-- The score is derived data and could in principle be recomputed on demand.
-- It is stored anyway, for two reasons the pipeline cannot satisfy otherwise:
--
--   1. Trend. §18 wants a dashboard showing whether a project is getting
--      better or worse, and that is a question about history. Recomputing
--      today's engine against yesterday's findings would answer a different
--      question -- "what would we say now" rather than "what did we say then".
--   2. Audit. A gate result (§12) is a decision made at a moment, and §15.6
--      requires security-sensitive decisions be reconstructible. A score that
--      only ever exists in memory cannot be produced when someone asks why a
--      release was blocked in September.
--
-- See docs/architecture/risk-engine.md and ADR 019.

CREATE TABLE scan_risk_scores (
    -- One score per scan. A re-run of the same scan replaces it rather than
    -- appending, so the history is one point per scan and not per attempt.
    scan_id    uuid PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    -- 0 (secure) to 100 (critical), §10's scale.
    score numeric(5,2) NOT NULL,
    -- The aggregate before saturation. Kept because score stops separating
    -- projects near 100 while total keeps rising: "did this get worse?" is
    -- still answerable at the top of the scale.
    total numeric(16,4) NOT NULL,

    -- What the score was computed over. A score of 12 from three findings and
    -- a score of 12 from three hundred are different situations.
    live_findings      integer NOT NULL,
    dismissed_findings integer NOT NULL,

    -- The digest of the weight configuration in force. Weights are tunable by
    -- design, which means a re-tuning makes older scores measurements of a
    -- different thing; without this, a trend line drawn across a tuning change
    -- is fiction that looks like data.
    weights_digest text NOT NULL,

    computed_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_risk_scores_score_range CHECK (score >= 0 AND score <= 100),
    CONSTRAINT scan_risk_scores_total_non_negative CHECK (total >= 0),
    CONSTRAINT scan_risk_scores_counts_non_negative CHECK (
        live_findings >= 0 AND dismissed_findings >= 0),
    CONSTRAINT scan_risk_scores_digest_not_blank CHECK (
        length(btrim(weights_digest)) > 0)
);

-- The trend query: this project's scores, newest first.
CREATE INDEX scan_risk_scores_project_computed_idx
    ON scan_risk_scores (project_id, computed_at DESC);
