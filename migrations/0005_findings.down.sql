-- Rollback of 0005_findings.
--
-- This destroys every finding, every occurrence, every correlation link, and
-- the entire lifecycle history. None of it can be reconstructed by re-scanning:
-- a re-scan reproduces the findings that exist *now*, not when each was first
-- seen, not which scans reported it, and not why it was ever marked resolved,
-- acknowledged, or a false positive.
--
-- That history is the reason findings are worth storing at all. Take a dump
-- first (§17: security-relevant records are archived, not silently discarded).

DROP TABLE IF EXISTS finding_status_history;
DROP TABLE IF EXISTS finding_links;
DROP TABLE IF EXISTS finding_occurrences;
DROP TABLE IF EXISTS findings;

DROP TYPE IF EXISTS finding_relationship;
DROP TYPE IF EXISTS finding_confidence;
DROP TYPE IF EXISTS finding_severity;
DROP TYPE IF EXISTS finding_status;
