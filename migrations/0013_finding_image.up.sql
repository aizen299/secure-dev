-- 0013_finding_image: where a container finding lives.
--
-- Image targets arrive with ADR 025, and a container finding needs to say which
-- image it is in. That fact is already inside the finding's identity, through
-- the repository being part of the fingerprint -- but a fingerprint is a hash,
-- so without this column "show me everything wrong with ghcr.io/org/api" is a
-- question the database cannot answer.
--
-- Additive: every existing finding keeps its fingerprint, because the
-- repository is carried in the fingerprint's existing location field rather
-- than in a sixth one (ADR 025). Nothing is re-identified by this migration.

ALTER TABLE findings
    -- The repository only: `ghcr.io/org/api`, never `ghcr.io/org/api:1.2.3`.
    -- A tag would make this column disagree with the identity derived from it,
    -- and would change on every build.
    ADD COLUMN image text,

    -- NULL means "not a container finding", which is why there is no default
    -- and no NOT NULL. An empty string would claim an image named "".
    ADD CONSTRAINT findings_image_not_blank CHECK (
        image IS NULL OR length(btrim(image)) > 0),

    -- Bounded like every other externally-sourced text column (§15.8). 255 is
    -- the limit the target validator already applies to a whole reference, so
    -- a repository alone cannot exceed it.
    ADD CONSTRAINT findings_image_length CHECK (
        image IS NULL OR length(image) <= 255);

-- Justified by a real query pattern (§17), and by an architectural decision:
-- ADR 025 declines to add an `image:` correlation key, on the grounds that
-- "these findings are in the same image" is a filter rather than a
-- relationship. This index is what makes that the right call -- it is how the
-- filter is served.
--
-- Partial, because only container findings have an image and they are a
-- minority of rows.
CREATE INDEX findings_project_image_idx
    ON findings (project_id, image)
    WHERE image IS NOT NULL;
