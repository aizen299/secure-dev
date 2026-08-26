# ADR 002: PostgreSQL as the system of record

- **Status:** Accepted
- **Date:** 2026-08-26

## Context

The SecureOps domain is strongly relational: projects contain repositories,
repositories have scans, scans produce findings, findings belong to assets and
correlate with other findings, and every one of those relationships is queried.

Findings also have a lifecycle (`OPEN → ACKNOWLEDGED → … → RESOLVED`) whose
transitions must be auditable, and the platform must answer historical questions
such as risk-score trend over time.

## Decision

Use **PostgreSQL** as the single durable store, accessed through **pgx**, with
schema changes as versioned migrations under `migrations/`, each with a
rollback.

Migrations run through a dedicated `cmd/migrate` binary rather than implicitly
at API startup, so applying a schema change is a deliberate operational act.

## Alternatives considered

- **MongoDB** — attractive early because scanner outputs are heterogeneous JSON,
  but the value of SecureOps is precisely that it *normalizes* that
  heterogeneity. Storing raw documents would push scanner-specific shapes
  downstream, which §7 forbids. Correlation across findings is a join-heavy
  workload.
- **SQLite** — fine for a single-node demo, but the platform runs an API plus
  multiple concurrent workers against shared state.
- **Postgres plus a separate document store for raw output** — rejected for
  Phase 1 as premature. Raw scanner output is persisted size-capped in Postgres;
  if volume later justifies object storage, that is its own ADR.

## Consequences

- Parameterized queries only (§15.9). pgx's extended protocol enforces this: it
  will not execute a concatenated multi-statement string.
- `jsonb` covers genuinely schemaless corners (per-scanner results, scan
  summaries) without abandoning the relational model.
- Every schema change needs a forward and a rollback migration, verified in CI.
- Constraints (`CHECK`, foreign keys, enums) put domain invariants in the
  database, so a bug in application code cannot persist a nonsensical scan state.
