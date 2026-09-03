-- Rollback of 0012_transition_notes.
--
-- This drops the reasoning behind every human judgement while keeping the
-- judgements themselves. A finding stays dismissed and the record of why stops
-- existing, which is a worse state than either having both or neither: the
-- decision survives with nothing supporting it.
--
-- Export finding_status_history first if any finding has been dismissed.

ALTER TABLE finding_status_history
    DROP CONSTRAINT IF EXISTS finding_status_history_note_length,
    DROP CONSTRAINT IF EXISTS finding_status_history_note_not_blank;

ALTER TABLE finding_status_history
    DROP COLUMN IF EXISTS note;
