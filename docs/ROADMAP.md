# SecureOps roadmap

Where the project stands, what is left, and what is deliberately not on the
list. Updated at the end of each phase.

Authoritative on sequencing; [CLAUDE.md](../CLAUDE.md) §26 is authoritative on
what each phase contains, and the
[threat model](security/threat-model.md) on what is and is not defended.

**Last updated: 2026-09-05**, after Phase 11.

---

## Where we are

**Ten of thirteen phases complete** — 1 through 9, and 11. The pipeline in
CLAUDE.md §3 runs end to end: a target goes in; a risk score, a ranked list of
fixes, and a PASS/WARN/FAIL verdict come out.

Threat model: **40 Mitigated · 17 Partial · 1 Open · 2 Prospective.**

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3a | Scan API and interim authentication | done |
| 3b | Six adapters: gitleaks · syft · grype · semgrep · trivy · zap | done |
| 4 | Normalization: canonical Finding, fingerprinting, dedup, persistence | done |
| 5 | Correlation: contextual issues, cross-domain escalation | done |
| 6 | Threat intelligence (EPSS) and the contextual risk engine | done |
| 7 | Remediation: vendor fix facts, consolidated actions, ranking | done |
| 8 | Policy engine: PASS/WARN/FAIL gates, durable audit log | done |
| 9 | Dashboard: posture, triage, issues, remediation, URL-bar scanning | done |
| 11 | Identity: accounts, roles, project scoping, administration | done |
| **10** | **CI/CD integration** | **next** |
| 12 | Kubernetes | not started |
| ~~13~~ | ~~Observability~~ | **dropped** — [ADR 034](adr/034-no-observability-phase.md) |
| 14 | Final hardening and documentation | not started |

Two sequencing decisions worth knowing, both recorded rather than silent:

- **Phase 3 was split into 3a and 3b.** The specification's phase list never
  named an endpoint that creates a scan, so the scan API is recorded as its own
  step rather than folded into a phase that did not describe it (CLAUDE.md §26).
- **Phase 11 ran before Phase 10.** CI needs a credential confined to specific
  projects, and confinement was Phase 11's work. Handing CI a credential that
  reached every project would have shipped the exposure T-23 describes.

---

## Phase 10 — CI/CD integration · next

The largest functional gap in the product. The gate computes a verdict and
nothing carries it anywhere: SecureOps can say a build should fail, and cannot
fail one.

**Build**

- `cmd/cli/` — the CI client. Submits a scan, polls it, prints the gate result,
  exits non-zero on FAIL. The first new binary since `cmd/useradd`.
- A GitHub Action wrapping it.
- PR comments (human-readable) and status checks (machine-readable), rendered
  from the same conditions so the two cannot disagree (§12).

**Depends on** the `service` token scoping from
[ADR 033](adr/033-identity-roles-and-project-scoping.md) change A: a CI
credential reaches only the projects it was granted, and cannot edit the policy
that judges it.

**Constraints** — §16, and they are the point rather than paperwork. CI is
attack surface: `permissions: contents: read` by default with scopes added only
on the job that needs them, third-party actions pinned to commit SHAs rather
than tags, and no secret exposed to a `pull_request` workflow from a fork.

**Done when** a pull request in this repository is blocked by SecureOps
scanning this repository.

---

## Phase 12 — Kubernetes

Every remaining security item lives here, because none of it is reachable
without a cluster.

- **T-10** — the one Open threat. Scanner binaries are not provenance-verified;
  the fix is digest-pinned images.
- **T-51** — archive expansion ratio. The image size cap bounds the
  *compressed* size a manifest declares; a layer that decompresses far larger is
  bounded only by the disk trivy extracts into. Needs an ephemeral per-job
  filesystem.
- **`Capabilities.NetworkKinds` enforcement** — adapters declare which target
  kinds need egress and nothing reads the declaration. Honest metadata awaiting
  a network policy.
- Ephemeral scanner Jobs, security contexts, resource limits, Helm.

---

## Phase 14 — Final hardening and documentation

Threat model review, architecture docs, an OpenAPI audit, and a full security
review of the finished system.

---

## Not on the phase list

Product gaps rather than plan items. None blocks a phase; each is a judgement
call about what SecureOps should be, and is recorded here so that choosing not
to do it stays a choice rather than an oversight.

### Worth the most

**SBOM component storage.** Syft's output is persisted as a raw result and
nothing parses it into queryable components. So correlation cannot ask the
question that separates a real finding from a theoretical one — *is this
vulnerable package actually present in the built image?* — and remediation
cannot reason about transitive dependencies, so an upgrade action speaks only
about the package it names.

This is the largest available gain in the product's core claim, and it is not
in any phase. It plausibly outranks Phase 12 on value, though not on risk.

### Trust-surface decisions

**Active scanning and authenticated DAST.** SecureOps does not test for
injection. ZAP's `activeScan` job is absent from the plan rather than disabled
in it, and its rules are absent from the worker image
([ADR 026](adr/026-dast-passive-only.md)). Active scanning delivers payloads to
a live application and writes to real forms; permission to do that is a fact
about who owns a deployment, not a flag on a scan, so it needs a per-project
authorization model that does not exist. Authenticated scanning needs
credentials workers deliberately do not hold (§14.7).

**Private registries.** Image scanning is public-only. Workers hold no registry
credentials and the trivy environment is an allow-list that cannot carry any.
Granting them is new trust surface, not a configuration change.

**Project scoping for machine credentials.** A `service` token is scoped by
configuration rather than membership, so rotating what a CI job may reach is an
edit to `SECUREOPS_API_TOKENS` and a restart.

### Identity conveniences

**Self-service on an account.** Nobody can change their own password or display
name, and there is no reset flow — a reset needs a delivery channel the product
does not have. An administrator creates accounts and changes roles.

**Per-session revocation.** Sessions are stateless, so one cannot be revoked
individually; disabling the person revokes all of them, and takes effect on
their next request. The cost of not having a sessions table.

**`admin` is global.** An administrator reaches every project by definition, so
a project cannot have its own administrator who is not also everyone else's. A
deliberate simplification for a single-team tool; the alternative is a tenancy
model.

**Project membership is edited through the API**, not the Access screen:
`PATCH /api/v1/users/{id}` with a `projects` array.

### Process gaps

**No approval step on a dismissal.** One `service` credential can dismiss a
finding and nobody countersigns. Every dismissal is audited, attributed and
reversible — but detection is not prevention, and an `ignored` finding never
expires.

**Risk weights are uncalibrated against real projects.** They are configuration
with the reasoning for every constant written down
([risk-engine](architecture/risk-engine.md)), so the ordering is trustworthy
and the absolute numbers are not. Correcting them needs evidence from real
estates, not argument.

**Corroboration counts distinct names, not distinct evidence.** Grype and Trivy
read overlapping advisory feeds, so their agreement is weaker than it looks.
Bounded by capping the raise at one step.

**Shallow clones, so no git history.** A credential committed and later removed
is not found. Full history would multiply clone size and time for untrusted
input.

**No project deletion.** Archiving is the only removal, by design: §17 requires
security-relevant records to be soft-deleted, and a project's scans, findings
and audit trail are exactly that.

---

## Dropped

**Phase 13 — Observability.** Removed on 2026-09-05
([ADR 034](adr/034-no-observability-phase.md)). Most of what the phase named
already shipped in Phases 1 and 2 — structured logging, health checks, and
per-scan telemetry persisted in `scan_results` — and what remained was a
Prometheus endpoint and OTel tracing that answer no question anybody is asking
about a single-operator tool. A metrics endpoint on a security tool is also a
disclosure surface that must be authenticated whether or not anybody reads it.

Where an operational question arises, the answer is to add the one measurement
that answers it, not to adopt a metrics stack. That is §4's own rule.
