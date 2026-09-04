# ADR 034: No observability phase

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

[CLAUDE.md](../../CLAUDE.md) §26 lists fourteen phases, and Phase 13 is
"Observability: structured logging, metrics, health checks, tracing where
justified". The specification names the same. This ADR removes that phase.

The decision is the project owner's (§24: "Claude Code does not unilaterally
redefine architecture"), taken on 2026-09-05 with the reasoning that
observability "serves no purpose" here and is "redundant overhead". This
records it, and the two facts that make it defensible rather than merely
convenient.

**The first: most of Phase 13 already shipped, in Phases 1 and 2.** The phase
list was written before the foundation existed and did not know that. What
exists today:

- **Structured logging** — `internal/logging`, `slog` with a configurable
  level and format, and secret redaction in the config it prints at startup.
- **Health checks** — `/healthz` (liveness) and `/readyz` (readiness, which
  probes PostgreSQL and Redis).
- **Per-scan telemetry, persisted** — `scan_results` carries `duration_ms`,
  `exit_code`, `scanner_version` and `started_at` per scanner, per scan. This
  is better than a metrics scrape for the questions this product actually
  raises, because it is attached to the scan it describes and survives.
- **A durable audit log** (ADR 022) — who did what, when, and to what.

What Phase 13 would have added on top is a Prometheus endpoint and OTel
tracing. Nothing else.

**The second: neither answers a question anybody is asking.** Metrics and
traces earn their cost where there is an SLO to defend, an on-call rotation to
page, or enough traffic that aggregate behaviour differs from individual
behaviour. SecureOps has none of those. It is a single-operator tool whose
slowest operation is a scan that already records its own duration.

§4 already says the quiet part: observability should be "proportional — do not
build an observability platform". A phase whose remaining content is a metrics
endpoint nobody reads is the opposite of proportional.

## Decision

**Phase 13 is removed from the plan.** Fourteen phases become thirteen; the
numbering is left alone rather than renumbered, so that 12 and 14 keep meaning
what every existing document says they mean. Phase 13 is recorded as dropped,
not renumbered away.

Structured logging, health checks and scan telemetry remain and are maintained
as ordinary parts of the system, not as a phase.

**Where an operational question does arise, the answer is to add the one
measurement that answers it** — a counter, a log field, a column — not to
adopt a metrics stack. That is the same rule §4 states and the same one that
kept Kafka and Elasticsearch out.

## Alternatives considered

**Keep the phase and do it minimally.** A `/metrics` endpoint with a handful
of counters is perhaps a day's work. Rejected because the work is not the cost:
a metrics endpoint is a public surface that must be authenticated or firewalled
(an unauthenticated one on a security tool discloses scan volume, project
count, and failure rates), a dependency to keep patched, and a thing that looks
maintained whether or not anybody reads it. A control nobody consumes is worse
than an absent one, because it suggests coverage that does not exist.

**Fold it into Phase 14.** Rejected as the same decision with a less honest
label. If the work is not being done, the plan should say so.

**Defer it rather than drop it.** Rejected because "deferred" is what §26
already records for things that are coming, and this is not coming. An honest
"no" is more useful to a reader than an indefinite "later".

## Consequences

**What becomes easier.** The remaining plan is three phases: 10 (CI/CD), 12
(Kubernetes), 14 (final hardening). No Prometheus dependency, no OTel
dependency, no `/metrics` surface to authenticate.

**What becomes harder.** A future operational question — why is the queue
deep, which scanner is slow across projects — has to be answered from logs and
`scan_results` rather than a dashboard. That is a real cost and it is accepted
knowingly. For the questions asked so far, both sources have been enough.

**What this does NOT remove.** Two things that could be mistaken for
observability and are not:

- **The audit log** (ADR 022) is a security control, not telemetry. It answers
  "who changed this", is append-only, and is required by §15.6.
- **Degradation reporting** (ADR 010) is correctness, not monitoring. A scan
  that could not run a scanner must say so, because a quiet failure reads as a
  clean result.

Neither is affected.

**What would reverse this.** Multiple operators, a deployment somebody else
depends on, or a specific recurring question the logs cannot answer. Any of
those is a reason to add the measurement that answers it — and if enough of
them accumulate, to supersede this ADR rather than quietly reintroduce the
phase.
