-- 0012_transition_notes: room for the argument behind a judgement.
--
-- finding_status_history has recorded who, when, why, from, and to since Phase
-- 4, with `reason` drawn from a fixed vocabulary so it stays queryable. That
-- answers "show me everything dismissed as an accepted risk"; it does not
-- answer "accepted by whom, on what grounds".
--
-- Human transitions arrive with ADR 024, and a dismissal without its reasoning
-- is the kind of record that looks complete and settles nothing six months
-- later.

ALTER TABLE finding_status_history
    -- Optional: scan-driven transitions have no argument to make. A note is
    -- free text and is never parsed -- the queryable half is `reason`, and
    -- keeping them separate is what stops the vocabulary decaying into prose.
    ADD COLUMN note text,

    -- Bounded, because it is client-supplied (§15.8). Long enough for the
    -- actual reasoning, short enough that the column cannot be used as
    -- storage.
    ADD CONSTRAINT finding_status_history_note_length CHECK (
        note IS NULL OR length(note) <= 2000),
    -- An empty note is not a note. NULL says "none given", which is a
    -- different fact from a note somebody left blank.
    ADD CONSTRAINT finding_status_history_note_not_blank CHECK (
        note IS NULL OR length(btrim(note)) > 0);
