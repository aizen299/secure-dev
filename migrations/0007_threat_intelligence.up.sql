-- 0007_threat_intelligence: exploitation likelihood, with its provenance.
--
-- Severity says how bad a finding would be. Nothing in the schema said how
-- likely anyone is to exploit it, which is the factor §10's risk formula cares
-- most about and the one the model could not express.
--
-- Four columns rather than one number, because a bare float cannot carry the
-- three things that make a threat-intelligence value usable: whether it exists,
-- where it came from, and how old it is. See
-- docs/adr/018-threat-intelligence-is-its-own-attribute.md.

ALTER TABLE findings
    -- The absolute likelihood of exploitation in the next 30 days, 0..1.
    -- NULL means no signal, which is NOT the same as a low score: EPSS
    -- probabilities are genuinely small (0.073 is a real value for a critical
    -- vulnerability), so a 0 default would be indistinguishable from real data
    -- saying "essentially nobody is exploiting this".
    ADD COLUMN epss_probability numeric(6,5),
    -- The rank among all scored vulnerabilities, 0..1. Usually the more
    -- legible number for a human: 0.939 says "worse than 94% of everything
    -- scored" where 0.073 sounds like nothing.
    ADD COLUMN epss_percentile numeric(6,5),
    -- Where the value reached us from. Required whenever a value is present:
    -- a number with no provenance cannot be audited, aged out, or reconciled
    -- when two providers disagree.
    ADD COLUMN epss_source text,
    -- The model date the value came from. EPSS is recomputed daily.
    ADD COLUMN epss_observed_at timestamptz;

-- All four or none. This is the schema-level statement of the rule the Go
-- model encodes with a pointer: a half-populated threat-intelligence value is
-- a number of unknown origin, which looks like evidence without being any.
ALTER TABLE findings
    ADD CONSTRAINT findings_epss_all_or_nothing CHECK (
        (epss_probability IS NULL AND epss_percentile IS NULL
             AND epss_source IS NULL AND epss_observed_at IS NULL)
        OR
        (epss_probability IS NOT NULL AND epss_percentile IS NOT NULL
             AND epss_source IS NOT NULL AND epss_observed_at IS NOT NULL)
    ),
    ADD CONSTRAINT findings_epss_probability_range CHECK (
        epss_probability IS NULL OR (epss_probability >= 0 AND epss_probability <= 1)),
    ADD CONSTRAINT findings_epss_percentile_range CHECK (
        epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)),
    ADD CONSTRAINT findings_epss_source_not_blank CHECK (
        epss_source IS NULL OR length(btrim(epss_source)) > 0);

-- Partial: the risk engine reads findings that HAVE a likelihood signal, and
-- indexing the rows without one serves nothing.
CREATE INDEX findings_epss_probability_idx
    ON findings (project_id, epss_probability DESC)
    WHERE epss_probability IS NOT NULL;
