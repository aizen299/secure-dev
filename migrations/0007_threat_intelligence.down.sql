-- Rollback of 0007_threat_intelligence.
--
-- This drops observed threat-intelligence values and their provenance. Unlike
-- a finding's lifecycle history, the loss is recoverable: EPSS is re-read from
-- scanner output on the next scan, and the values are a snapshot of a model
-- that is recomputed daily anyway.
--
-- What is NOT recovered is the historical record of what the likelihood was
-- when a decision was made -- "we deprioritised this in September because
-- exploitation was unlikely then" becomes unanswerable. Take a dump first if
-- any scoring or gate decision has already been made against these values.

DROP INDEX IF EXISTS findings_epss_probability_idx;

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_epss_all_or_nothing,
    DROP CONSTRAINT IF EXISTS findings_epss_probability_range,
    DROP CONSTRAINT IF EXISTS findings_epss_percentile_range,
    DROP CONSTRAINT IF EXISTS findings_epss_source_not_blank;

ALTER TABLE findings
    DROP COLUMN IF EXISTS epss_probability,
    DROP COLUMN IF EXISTS epss_percentile,
    DROP COLUMN IF EXISTS epss_source,
    DROP COLUMN IF EXISTS epss_observed_at;
