-- Rollback of 0010_security_policies.
--
-- This drops every project's gate configuration and the record of every gate
-- decision made against it. Neither is recoverable: the policy was authored by
-- a human, and a past verdict cannot be recomputed because the findings it was
-- computed over have since changed status.
--
-- A release blocked or allowed by these results becomes unexplainable (§15.6).
-- Take a dump first.

DROP INDEX IF EXISTS policy_results_project_evaluated_idx;
DROP TABLE IF EXISTS policy_results;
DROP TYPE IF EXISTS policy_verdict;

DROP TRIGGER IF EXISTS security_policies_set_updated_at ON security_policies;
DROP TABLE IF EXISTS security_policies;
DROP TYPE IF EXISTS policy_level;
