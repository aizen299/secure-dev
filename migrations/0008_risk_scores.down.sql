-- Rollback of 0008_risk_scores.
--
-- This drops the score history permanently. Unlike raw scanner output, it
-- cannot be re-derived: the findings a past scan saw have since changed status,
-- the project's declared criticality may have moved, and the weights may have
-- been re-tuned. Recomputing after the fact answers "what would we say now",
-- which is not the same question.
--
-- Any gate decision already made against these scores becomes unexplainable
-- (§15.6). Take a dump first if one has.

DROP INDEX IF EXISTS scan_risk_scores_project_computed_idx;
DROP TABLE IF EXISTS scan_risk_scores;
