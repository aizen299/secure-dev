# ADR 003: Redis as the scan job queue

- **Status:** Accepted
- **Date:** 2026-08-26

## Context

Scans are long-running: a repository scan across Semgrep, Gitleaks, Syft, Grype,
and Trivy takes minutes. `POST /scans` must return `202 Accepted` immediately
(§13), so work has to be handed to a worker asynchronously.

The queue is also a trust boundary. Workers are the only component that touches
untrusted repository content (§14), so the API must communicate with them
through data, never by handing over executable behaviour.

## Decision

Use **Redis** as the job queue and transient-state store, with workers consuming
jobs and reporting status back through PostgreSQL.

Job payloads are plain data: scan ID, target reference, and scanner selection.
A payload never contains a command line, a script, or anything else a worker
would execute directly.

## Alternatives considered

- **PostgreSQL as the queue** (`SELECT … FOR UPDATE SKIP LOCKED`) — genuinely
  viable and would remove a dependency. Rejected because the specification names
  Redis, and because scan progress updates are high-frequency, transient writes
  that do not belong in the durable store.
- **Kafka** — explicitly rejected by §25.14. SecureOps needs a work queue, not
  an event-streaming platform with replayable partitioned logs.
- **RabbitMQ** — a capable broker, but heavier to operate than the workload
  warrants, and Redis additionally serves as the cache.

## Consequences

- The API never blocks on scanner execution; §25.2 is structurally enforced.
- Redis is not the system of record. Durable scan state lives in PostgreSQL, so
  losing Redis loses in-flight queue entries, not scan history.
- Job payloads are data-only, keeping the API/worker trust boundary intact.
- Requires explicit handling of at-least-once delivery: job handlers must be
  idempotent. Phase 2 owns that design.
