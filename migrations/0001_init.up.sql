-- 0001_init: foundational SecureOps entities.
--
-- Phase 1 establishes only the entities the API skeleton needs: projects, the
-- repositories they contain, and scans. Findings, correlation, risk, policy, and
-- audit tables arrive with the phases that own them (CLAUDE.md §17, §26).
--
-- Conventions: snake_case, plural table names, explicit foreign keys,
-- timestamptz stored in UTC.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Deployment context is a risk-engine input: a finding in production is not
-- equivalent to the same finding in a sandbox (§10).
CREATE TYPE project_environment AS ENUM ('development', 'staging', 'production');

-- Asset criticality feeds the contextual risk multiplier (§10).
CREATE TYPE asset_criticality AS ENUM ('low', 'medium', 'high', 'critical');

-- Scan states per §13. PARTIAL is distinct from COMPLETED on purpose: a scan
-- with a failed scanner must never be evaluated as if coverage were complete.
CREATE TYPE scan_status AS ENUM (
    'queued',
    'running',
    'partial',
    'completed',
    'failed',
    'cancelled'
);

CREATE TABLE projects (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    slug          text NOT NULL,
    description   text NOT NULL DEFAULT '',
    environment   project_environment NOT NULL DEFAULT 'development',
    criticality   asset_criticality NOT NULL DEFAULT 'medium',
    internet_facing boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    archived_at   timestamptz,

    CONSTRAINT projects_slug_key UNIQUE (slug),
    CONSTRAINT projects_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT projects_slug_format CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

CREATE TABLE repositories (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name           text NOT NULL,
    url            text NOT NULL,
    default_branch text NOT NULL DEFAULT 'main',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    archived_at    timestamptz,

    CONSTRAINT repositories_project_url_key UNIQUE (project_id, url),
    CONSTRAINT repositories_name_not_blank CHECK (length(btrim(name)) > 0)
);

CREATE INDEX repositories_project_id_idx ON repositories (project_id);

CREATE TABLE scans (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    repository_id uuid REFERENCES repositories (id) ON DELETE SET NULL,
    status        scan_status NOT NULL DEFAULT 'queued',
    commit_sha    text,
    branch        text,
    -- Results are only reproducible relative to the scanner versions that
    -- produced them, so versions are captured per scan (§7 rule 6).
    scanner_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Per-scanner outcome, so a partial failure stays visible (§13).
    scanner_results  jsonb NOT NULL DEFAULT '{}'::jsonb,
    summary          jsonb NOT NULL DEFAULT '{}'::jsonb,
    queued_at     timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    completed_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scans_commit_sha_format CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{7,64}$'),
    CONSTRAINT scans_completed_after_started CHECK (
        completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at
    ),
    -- A terminal scan must record when it terminated.
    CONSTRAINT scans_terminal_has_completed_at CHECK (
        status NOT IN ('partial', 'completed', 'failed', 'cancelled')
        OR completed_at IS NOT NULL
    )
);

CREATE INDEX scans_project_id_created_at_idx ON scans (project_id, created_at DESC);
CREATE INDEX scans_status_idx ON scans (status);
CREATE INDEX scans_repository_id_idx ON scans (repository_id);

-- Keep updated_at honest without relying on every caller to set it.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_set_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER repositories_set_updated_at
    BEFORE UPDATE ON repositories
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER scans_set_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
