-- 0014_finding_endpoint: where in a running application a DAST finding lives.
--
-- DAST arrives with ADR 026, and a finding against a live application needs to
-- say which endpoint it is on. The path is already inside the finding's
-- identity, through the fingerprint's location field -- but a fingerprint is a
-- hash, so without this column "show me everything wrong with /login" is a
-- question the database cannot answer.
--
-- Additive, and it re-identifies nothing: DAST findings are new, and every
-- existing finding keeps its fingerprint.

ALTER TABLE findings
    -- The request method and the URL path: `GET /login`. Deliberately NOT the
    -- origin, which churns whenever a CI preview environment mints a hostname,
    -- and deliberately NOT the query string, which is per-request noise and is
    -- where an application puts credentials (§15.3). What was pointed at is
    -- recorded on scans.target, which is where it belongs.
    ADD COLUMN endpoint text,

    -- NULL means "not a DAST finding". An empty string would claim an endpoint
    -- named "".
    ADD CONSTRAINT findings_endpoint_not_blank CHECK (
        endpoint IS NULL OR length(btrim(endpoint)) > 0),

    -- Bounded like every other externally-sourced text column (§15.8).
    ADD CONSTRAINT findings_endpoint_length CHECK (
        endpoint IS NULL OR length(endpoint) <= 2048);

-- Justified by a real query pattern (§17) and by an architectural decision:
-- ADR 026 declines to add an `endpoint:` correlation key, because only one
-- scanner populates endpoint locations and a single-category bucket asserts
-- nothing. This index is what makes that the right call -- it serves the
-- filter that the key would not have earned.
--
-- Partial, because only DAST findings have an endpoint.
CREATE INDEX findings_project_endpoint_idx
    ON findings (project_id, endpoint)
    WHERE endpoint IS NOT NULL;
