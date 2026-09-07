-- Rollback of 0017_sbom_components.
--
-- Loses every stored inventory. That is acceptable in a way most of these
-- rollbacks are not: a component row is derived entirely from a scan's raw
-- result, which is persisted verbatim and never discarded (§8). Reapplying the
-- migration and rescanning reproduces it; nothing here is a source of truth.
--
-- Findings, issues, risk scores and audit records are untouched -- no other
-- table references this one.

DROP TABLE IF EXISTS sbom_components;
