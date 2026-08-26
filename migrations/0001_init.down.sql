-- Rollback of 0001_init. Dropped in reverse dependency order.

DROP TRIGGER IF EXISTS scans_set_updated_at ON scans;
DROP TRIGGER IF EXISTS repositories_set_updated_at ON repositories;
DROP TRIGGER IF EXISTS projects_set_updated_at ON projects;

DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS projects;

DROP TYPE IF EXISTS scan_status;
DROP TYPE IF EXISTS asset_criticality;
DROP TYPE IF EXISTS project_environment;

-- pgcrypto is intentionally left installed: other migrations may rely on it.
