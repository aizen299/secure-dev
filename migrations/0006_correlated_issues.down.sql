-- Rollback of 0006_correlated_issues.
--
-- Safe to run, unlike 0005's rollback. Correlation is a pure function of the
-- findings that remain, and it is recomputed after every scan, so dropping
-- these tables loses no fact that cannot be regenerated -- the issues come back
-- on the next scan, identical, because the engine is deterministic.
--
-- What is lost until then is the ability to answer "what does SecureOps
-- currently consider one problem", so a rollback in production leaves the
-- dashboard and any policy gate reading issues without an answer.

DROP TABLE IF EXISTS correlated_issue_members;
DROP TABLE IF EXISTS correlated_issues;
