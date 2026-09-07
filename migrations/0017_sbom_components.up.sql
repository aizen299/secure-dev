-- 0017_sbom_components: what a scan found a project to be made of.
--
-- Syft has produced a CycloneDX SBOM for every repository and image scan since
-- Phase 3b, and nothing has ever read it. This is the table that makes it
-- queryable. See docs/adr/035-sbom-component-storage.md.
--
-- One table, not four. `findings` needs its split because a finding has an
-- identity that persists and an occurrence that moves; a component has neither.
-- It is a fact about one build, recorded once, never updated.

CREATE TABLE sbom_components (
    id bigserial PRIMARY KEY,

    -- The scan that observed it. Components are per scan (ADR 035 §1): an SBOM
    -- describes one build, and a row that outlived its scan would be an
    -- inventory nobody can reproduce.
    --
    -- ON DELETE CASCADE, unlike audit_logs' SET NULL: an audit record must
    -- survive what it describes, and an inventory of a scan that no longer
    -- exists describes nothing.
    scan_id uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,

    -- Denormalised from the scan so "what is in this project" needs no join.
    -- The component count dwarfs the finding count -- 52 components against a
    -- handful of findings in the scan that motivated this -- so the join this
    -- avoids is the expensive one.
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,

    -- The identity that matters. Grype and Trivy both emit purls byte for byte,
    -- which is what lets a dependency finding and a container finding meet on
    -- one key (ADR 025) -- and what will let a finding meet a component.
    --
    -- Empty rather than NULL when syft could not name one: a component it could
    -- not identify is still evidence of something present, and dropping it
    -- would make the inventory quietly incomplete.
    purl text NOT NULL DEFAULT '',

    name text NOT NULL,
    version text NOT NULL DEFAULT '',

    -- CycloneDX's component type: library, application, operating-system, file.
    -- Stored as text rather than an enum: it is a vendor's vocabulary, not
    -- ours, and a value we have not seen must not fail a scan.
    component_type text NOT NULL DEFAULT '',

    -- The CPE syft derives, kept because some advisory sources key on it where
    -- no purl exists.
    cpe text NOT NULL DEFAULT '',

    -- Where syft found it, relative to the scan root: `/requirements.txt`,
    -- `/go.mod`. Answers "which manifest declared this", which is the first
    -- question anybody asks about an unexpected dependency.
    --
    -- Already free of workspace paths: syft emits it relative to the scan
    -- source, and the adapter fails the scan if an absolute workspace path
    -- appears in its output at all (ADR 008).
    location text NOT NULL DEFAULT '',

    -- Which scanner produced this row. Syft today; trivy also emits CycloneDX,
    -- and an inventory that cannot say where a component came from cannot be
    -- reconciled when two disagree.
    scanner text NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sbom_components_name_not_blank CHECK (length(btrim(name)) > 0),
    CONSTRAINT sbom_components_scanner_not_blank CHECK (length(btrim(scanner)) > 0),
    -- Bounds on attacker-influenced text. Every value here is derived from a
    -- manifest inside an untrusted repository (§15.7, §15.8).
    CONSTRAINT sbom_components_name_length CHECK (length(name) <= 512),
    CONSTRAINT sbom_components_purl_length CHECK (length(purl) <= 1024),
    CONSTRAINT sbom_components_version_length CHECK (length(version) <= 256),
    CONSTRAINT sbom_components_type_length CHECK (length(component_type) <= 64),
    CONSTRAINT sbom_components_cpe_length CHECK (length(cpe) <= 1024),
    CONSTRAINT sbom_components_location_length CHECK (length(location) <= 1024)
);

-- Reading one scan's inventory, which is what the scan page asks for.
CREATE INDEX sbom_components_scan_idx ON sbom_components (scan_id);

-- "What is in this project", newest scan first.
CREATE INDEX sbom_components_project_idx ON sbom_components (project_id, id DESC);

-- The join correlation will need: "does this scan contain the package this
-- finding names". Built now because adding it later means adding it to a table
-- that has grown, and because the query it serves is the reason this table
-- exists (ADR 035 §6).
CREATE INDEX sbom_components_purl_idx ON sbom_components (scan_id, purl)
    WHERE purl <> '';
