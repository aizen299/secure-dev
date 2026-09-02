# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phases 1-6 are complete. Point SecureOps at a repository and it returns one
contextual risk score, with every number traceable to the finding that produced
it.**

Five scanners run in isolated workers; their output is normalized into one
canonical finding model, deduplicated, correlated into contextual issues,
scored, and turned into ranked work. What is missing from the pipeline in
CLAUDE.md §3 is the policy gate (Phase 8), so SecureOps can tell you how bad a
project is and what to fix first, but not yet fail your build over it.

Phase 3 is split into 3a and 3b below. The specification's phase list names only
the adapters, so the scan API is recorded as its own step rather than folded
silently into a phase that did not describe it; see [CLAUDE.md](CLAUDE.md) §26.

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3a | Scan API and interim authentication | done |
| 3b | Repository fetching + **Gitleaks** adapter | done |
| 3b | **Syft** adapter (SBOM) | done |
| 3b | **Grype** adapter (known vulnerabilities) | done |
| 3b | **Semgrep** adapter (SAST) | done |
| 3b | **Trivy** adapter (IaC and config misconfiguration) | done |
| 3b | Remaining: Trivy image targets, then ZAP | later |
| 4 | **Normalization**: canonical Finding, fingerprinting, deduplication | done |
| 4 | **Findings persistence**: lifecycle across scans, API | done |
| 5 | **Correlation**: contextual issues, cross-domain links, severity escalation | done |
| 6 | **Threat intelligence**: EPSS capture with provenance | done |
| 6 | **Risk engine**: contextual scoring, max-dominant aggregation | done |
| 7 | **Remediation**: vendor fix facts, consolidated actions, ranking | done |
| 8 | Security policy engine and gates | next |
| 9–14 | Dashboard, CI/CD, hardening, Kubernetes, observability | not started |

Underneath is the `Scanner` interface with capability-driven selection, a
validated `Target` model (SSRF, path traversal, and argument-injection
defences), argv-only subprocess execution with resource limits, ephemeral
per-job workspaces, the scan lifecycle with `PARTIAL` semantics, a Redis job
queue, and the worker binary.

`POST /api/v1/scans` returns **202** with a scan id and enqueues the work; the
request never blocks on scanner execution. Projects can be created and listed,
scan history is queryable, and a failed scan records *why* it failed instead of
reporting a bare `failed`.

Every `/api/v1` endpoint except health requires a bearer token. Shipping write
endpoints with no authentication was not an option, and waiting for Phase 11's
full RBAC would have meant doing exactly that. The gate is deliberately interim;
see [ADR 006](docs/adr/006-interim-bearer-token-auth.md) for what it does and
does not buy.

Submit a repository and the worker clones it into an ephemeral workspace and
runs the adapters against the checkout. Gitleaks covers secrets — verified
against a public repository of planted secrets: 22 detected, locations and rules
retained, **zero credentials persisted**.

That last part is the design, not a coincidence. Gitleaks output contains the
credentials it finds, and storing them would turn SecureOps into a database of
harvested secrets — the worst possible outcome for a tool meant to prevent
exactly that. So the value is redacted inside the scanner process, and the
adapter refuses to return output it cannot prove is redacted.
[ADR 007](docs/adr/007-secret-redaction-in-raw-results.md) has the reasoning,
including the part where being *too* strict discarded real findings.

Syft now runs alongside it, producing a CycloneDX SBOM of what the repository
is built from. It is the odd adapter out: it reports no findings, because
nothing in a bill of materials is *wrong* — it is the input the dependency and
license analysis in later phases consume.

Grype matches dependencies against known advisories, and it is the first
adapter whose answer depends on data it did not derive from the target. The
same repository scanned with a five-day-old vulnerability database yields fewer
findings than it should, and every one of them is still correct — the report is
short, not wrong.

Grype ships a guard for this and it fails the scan outright, discarding real
findings. SecureOps turns that guard off and applies the same threshold itself,
marking the result `stale_vulnerability_db` instead: the findings are kept, the
scan settles at `PARTIAL`, and a gate can say exactly why it should not be
trusted. The 2 GB database is provisioned once at worker startup, before any job
is claimed, so scans of untrusted repositories reach no network at all.

Semgrep adds static analysis, and it is the first adapter that is not Go. It
cannot be built from source with our own toolchain the way the others are, so it
is installed from the PyPI wheel with that wheel's SHA-256 verified against the
digest PyPI publishes — a weaker guarantee than a pinned commit, recorded as
such in ADR 014 rather than glossed over.

It also has a property none of the others do: its findings can carry the matched
source line, and for a rule that fires on a credential that line *is* the
credential. Unauthenticated semgrep withholds it, but that follows from its login
state rather than from any flag, so the adapter checks every finding before
persisting and discards the whole result if any carries source.

Trivy covers misconfiguration — Dockerfiles, Kubernetes manifests, Terraform —
and nothing else. It can also scan for dependency vulnerabilities and secrets,
and is deliberately asked for neither: Grype and Gitleaks already own those
domains, and §6 forbids duplicating coverage without a reason.

It is the only adapter whose stored output is not byte-identical to what the
scanner emitted. Trivy quotes the source lines that caused each finding, and for
infrastructure-as-code those lines are routinely a credential, so the adapter
redacts them before anything is persisted and then checks that it worked
(ADR 015).

Scanner output now becomes findings. A finding has a stable identity that
survives re-scanning — deliberately excluding line numbers, so code moving down
a file does not restart its history — which is what makes `resolved` and
`reopened` mean anything. Two scanners reporting one CVE on one package produce
one finding with two sources rather than two findings.

A finding is marked resolved only when every scanner that reported it completed
successfully and none of them saw it again. A scanner that failed resolves
nothing, so a degraded scan can never read as "fixed".

Read them at `GET /api/v1/projects/{id}/findings` and
`GET /api/v1/scans/{id}/findings`. See
[docs/architecture/fingerprinting.md](docs/architecture/fingerprinting.md) for
what identity is built from and, more importantly, what it deliberately leaves
out.

Findings then become **issues**. Several findings that share a vulnerability, a
component, or a file are one problem, and an issue whose members span two
security domains is rated one step above the worst of them — a vulnerable
dependency that code also misuses is worse than either fact alone. That derived
severity is a severity, not a risk score; the 0–100 project score is a separate
engine that consumes issues rather than competing with them.

Issues link findings; they never replace them. Every member keeps its own
severity, its own scanner, and its own remediation, and every membership carries
the evidence for it in prose — SecureOps does not assert a relationship it
cannot explain. Grouping is per shared attribute rather than by transitive
closure over the link graph, so two findings never end up in one issue on the
strength of a chain no rule evaluated.

Read them at `GET /api/v1/projects/{id}/issues`. The rules, the escalation
ladder, and the correlations that are *not* reachable yet are in
[docs/architecture/correlation.md](docs/architecture/correlation.md).

Findings also carry **threat intelligence**: how likely exploitation is, as
opposed to how bad it would be. EPSS — the FIRST.org exploitation-probability
model — is captured from scanner output with its source and its model date,
because a likelihood with no provenance cannot be aged out or reconciled when
two providers disagree.

Absent is `null`, never zero. EPSS probabilities are genuinely small — 0.073 is
a real value for a critical vulnerability — so a zero default would be
indistinguishable from real data saying "essentially nobody is exploiting this".
The Go model uses a pointer, the API omits the field entirely, and the database
enforces all-four-or-none. For the same reason, EPSS is never multiplied into a
severity weight; see
[ADR 018](docs/adr/018-threat-intelligence-is-its-own-attribute.md).

Findings, issues, and threat intelligence then become **one number**. The risk
engine scores each finding as

```text
risk = SeverityWeight × Exploitability × Exposure × AssetCriticality × Confidence
```

and aggregates a project as `max + 0.15 × (Σ − max)`, saturated onto 0–100. Each
factor is a multiplier around a documented neutral point, so a factor with no
data contributes exactly 1.0 and cannot quietly move a score. Every factor is a
*gate*: a critical in a throwaway sandbox scores 10.0 where the same finding on
an internet-facing production asset under active exploitation scores 81.3.

Aggregation is max-dominant rather than a plain sum for a reason that only shows
up arithmetically. Summation makes volume and severity interchangeable — an
earlier draft of this design scored 500 informational findings at 71.3 against
56.7 for the worst finding the model can express. Max-dominance makes the worst
finding the floor and everything else pressure above it; the crossover where
trivia outranks a crisis moves from 335 findings to roughly 44,700, and where
it still exists it is published rather than claimed away.

The engine is pure and deterministic — same findings, same score, always — and
**no AI or heuristic model influences it**. Adding a finding can never lower a
project's score, which is proved rather than sampled. Every score carries the
factor values that produced it, including which were neutral for lack of data,
so a gate result can be argued with instead of merely reported.

Read it at `GET /api/v1/projects/{id}/risk`, which returns the current score,
the aggregate before saturation, and the trend. A project that has never been
scored returns **404, never zero**: "we have not assessed this" and "we assessed
it and it is clean" are different claims. The formula, every weight, the derivation
of every constant, and what the engine deliberately does not compute are in
[docs/architecture/risk-engine.md](docs/architecture/risk-engine.md) and
[ADR 019](docs/adr/019-risk-scoring-and-aggregation.md).

And a score raises a question it cannot answer, so the last engine answers it:
**what should I do first?**

The unit is an action, not a finding. One `npm upgrade` may close five findings
reported by two scanners, and it appears once — that consolidation is the
fragmentation this product exists to remove. Actions are ranked by **risk
removed**: how far the project score would actually fall if you took them,
computed by rerunning the risk engine without that action's findings. That is
deliberately not the sum of their risk. Aggregation is max-dominant, so removing
the single finding holding a project's floor can beat clearing six lesser ones
that add up higher.

The facts come from the vendor, not from us. Grype reports the version that
fixes a vulnerability and its fix *state*, and SecureOps had been discarding
both since Phase 3b — the most actionable fact the platform can obtain never
reached the model. It does now, as four states rather than a boolean, because
"no fix yet", "there will never be one", and "nobody told us" lead to three
different decisions and collapsing them is how a tool ends up recommending an
upgrade to a version that does not exist.

**Nothing is ever invented.** An action names no version no scanner reported,
and where several versions fix several advisories it lists them rather than
choosing — picking one needs ecosystem-specific version ordering, and a
comparator correct for semver is wrong for PEP 440 or Debian epochs. Every
statement carries its source: `vendor`, `scanner`, or `derived`. `ai_explanation`
is declared so AI content would be visible if it were ever added, and is never
produced.

Read it at `GET /api/v1/projects/{id}/remediation`. The action model, the
ranking, and what the engine refuses to do are in
[docs/architecture/remediation.md](docs/architecture/remediation.md) and
[ADR 020](docs/adr/020-remediation-actions-and-prioritization.md).

**Five scanners are registered: Gitleaks, Syft, Grype, Semgrep, and Trivy.** A
repository scan today means secret scanning, an SBOM, known-vulnerability
matching, static analysis, and misconfiguration — no container images, no DAST.
Adding an adapter is one line in [cmd/worker/main.go](cmd/worker/main.go) plus
its own package.

Security gates are **not implemented**. See
[the specification](docs/SecureOps_Claude_Code_Project_Specification.md) for the
full plan and [CLAUDE.md](CLAUDE.md) §26 for the phase breakdown.

## Requirements

Go 1.27+ · Node 26+ · Docker with Compose · PostgreSQL 17 · Redis 8

Security tooling for the self-scan: gitleaks, semgrep, syft, grype, trivy.

Run `make tools` to check what is present.

## Quick start

```bash
cp .env.example .env
```

Edit `.env` and replace every placeholder value. `.env` is gitignored and must
never be committed.

```bash
make up
```

This builds the images, starts PostgreSQL and Redis, applies migrations, and
starts the API and dashboard.

- Dashboard: <http://localhost:3000>
- API liveness: <http://localhost:8090/healthz>
- API readiness: <http://localhost:8090/readyz>

The API is published on **8090**, not 8080. Go binds `":8080"` as the
dual-stack wildcard, which succeeds even when another process already holds
`127.0.0.1:8080` — the two sockets do not collide. The result is split-brain
routing where `localhost:8080` and `127.0.0.1:8080` reach different servers,
and nothing fails loudly. `.env.example` explains which of the three port
settings does what.

## Using the API

Every `/api/v1` endpoint except health requires a bearer token. Generate one,
put it in `.env` as a `label:secret` pair, and the API will refuse to start
without it:

```bash
echo "SECUREOPS_API_TOKENS=local-dev:$(openssl rand -hex 32)" >> .env
```

Create a project — its environment, criticality, and internet exposure are risk
engine inputs, not decoration:

```bash
curl -sS -X POST http://localhost:8090/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Payments API","environment":"production","criticality":"critical","internet_facing":true}'
```

Submit a scan. This returns `202` immediately with a scan id; it does not wait
for scanners to run:

```bash
curl -sS -X POST http://localhost:8090/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"project_id":"<uuid>","target":{"kind":"repository","repository_url":"https://github.com/acme/app"}}'
```

Poll it:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/scans/<uuid>
```

The scan settles at `completed`, or at `partial` when a scanner failed or was
skipped. `partial` is never a synonym for `completed`: the per-scanner status,
exit code, and structured reason are all recorded, so a degraded scan says so.

Then read what it found. Three views of the same evidence, narrowing as you go:

```bash
# Every finding, canonical and deduplicated across scanners.
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/projects/<uuid>/findings

# Contextual issues: findings that share a CVE, a component, or a file,
# treated as one problem and escalated when they span security domains.
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/projects/<uuid>/issues

# One number, with the trend behind it.
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/projects/<uuid>/risk
```

The risk response carries more than the score. `total` is the aggregate before
saturation, which keeps separating projects after `score` flattens near 100.
`complete` says whether the score rests on a full scan — a scanner that crashed
reports nothing, and fewer findings look exactly like an improvement.
`weights_digest` identifies the configuration it was computed under, because
scores across a re-tuning are not comparable.

A project that has never been scored returns **404, not a score of zero**.

The full contract is in [docs/api/openapi.yaml](docs/api/openapi.yaml).

## Development

```bash
make check
```

Runs formatting, `go vet`, golangci-lint, Go tests with the race detector, and
the web lint and type-check.

```bash
make security
```

Runs the self-scan: gitleaks, semgrep, trivy, and syft/grype. SecureOps scans
SecureOps.

```bash
make scan-image
```

Scans the built container images. Deliberately **not** part of `make security`,
which must stay fast enough to run before every commit — CI runs it instead, so
the coverage is automatic. This matters: the published gitleaks binary carried
32 HIGH/CRITICAL CVEs and `trivy fs` does not look inside images.
[ADR 009](docs/adr/009-build-scanners-from-source.md) covers the fix.

```bash
make test-integration
```

Runs the integration tests against a live PostgreSQL and Redis — start the
stack with `make up` first. They are behind an `integration` build tag so
`go test ./...` stays hermetic.

Run `make help` for the full target list.

## Architecture

```text
Next.js UI  ──►  Go API  ──┬──►  PostgreSQL   (durable domain state)
                           └──►  Redis queue  ──►  Scanner Workers (isolated)
```

The API orchestrates and never executes untrusted target content. Scanner
execution is isolated in workers. See [CLAUDE.md](CLAUDE.md) §3 and §14.

## Repository layout

```text
cmd/api/          API server
cmd/worker/       scan worker; scanner adapters are registered here
cmd/migrate/      migration runner
internal/
  scanners/       Scanner contract, Target validation, registry, safe exec
    gitleaks/     secret scanning, with the ADR 007 redaction control
    syft/         CycloneDX SBOM generation
    grype/        known-vulnerability matching, EPSS capture
    semgrep/      SAST against pinned rulesets
    trivy/        IaC and config, with the ADR 015 line redaction
  normalization/  raw output -> canonical Finding, fingerprinting, dedup (pure)
  correlation/    contextual issues, cross-domain links (pure)
  risk/           deterministic contextual scoring (pure)
  remediation/    consolidated actions, ranked by risk removed (pure)
  findings/       findings, issues, and score persistence; lifecycle
  scans/          scan lifecycle and persistence
  queue/          scan job queue (Redis, plus in-memory for tests)
  worker/         job runner: concurrency, timeouts, failure isolation
  netguard/       SSRF address policy
  auth/           interim bearer-token verification (ADR 006)
  fetch/          git clone into the ephemeral workspace (ADR 008)
  projects/       project entity, validation, persistence
  httpapi/        routing, middleware, auth gate, handlers, health
  config/ logging/ storage/
apps/web/         Next.js dashboard
migrations/       SQL migrations (forward + rollback)
deployments/      Dockerfiles
tests/fixtures/   captured scanner output, including hostile cases
tests/integration/ tests against real PostgreSQL and Redis
docs/             specification, ADRs, architecture, security
```

Scanner-specific knowledge lives only under `internal/scanners/<name>/`. The
`scanners` root package holds the contract and must never import an adapter or
branch on a scanner's name.

## Documentation

- [CLAUDE.md](CLAUDE.md) — architecture and engineering rules
- [Specification](docs/SecureOps_Claude_Code_Project_Specification.md)
- [API reference](docs/api/openapi.yaml) — OpenAPI 3.1, kept in sync with the
  handlers; an API change without a spec change is incomplete
- [Architecture](docs/architecture/) — the three deterministic engines, each
  specified before it was implemented:
  [fingerprinting](docs/architecture/fingerprinting.md),
  [normalization](docs/architecture/normalization.md),
  [correlation](docs/architecture/correlation.md), the
  [risk engine](docs/architecture/risk-engine.md) — the formula, every weight,
  and the derivation of every constant — and
  [remediation](docs/architecture/remediation.md)
- [Architecture decision records](docs/adr/) — twenty, written before the
  decisions they record. The ones that most shape the system:
  [scanner isolation](docs/adr/004-scanner-isolation.md),
  [secret redaction](docs/adr/007-secret-redaction-in-raw-results.md),
  [building scanners from source](docs/adr/009-build-scanners-from-source.md),
  [the API contract enforced by tests](docs/adr/011-api-contract-enforced-by-tests.md),
  [the canonical finding model](docs/adr/016-canonical-finding-model-and-fingerprint.md),
  [correlation semantics](docs/adr/017-correlation-issues-and-severity.md),
  [threat intelligence as its own attribute](docs/adr/018-threat-intelligence-is-its-own-attribute.md),
  [risk scoring](docs/adr/019-risk-scoring-and-aggregation.md),
  and [remediation actions](docs/adr/020-remediation-actions-and-prioritization.md)

### Security documentation

- [Threat model](docs/security/threat-model.md) — 45 threats across seven trust
  boundaries, each labelled mitigated, partial, or open, with the test that
  enforces it
- [Security model](docs/security/security-model.md) — assets, adversaries, and
  which controls actually exist today
- [Trust boundaries](docs/security/trust-boundaries.md)

### Known limitations

- **No authorization.** Authentication exists, authorization does not. Every
  valid token reaches every project: there is no tenancy boundary and no role
  model, so this is safe only for a single-tenant deployment. Tracked as T-23;
  Phase 11 addresses it.
- **The bearer-token gate is interim.** A token labels a client, not a person,
  so scan attribution is only as precise as that label. There is no rotation
  mechanism and no revocation short of a restart. Overlapping tokens are
  supported, so a rotation need not be a hard cutover.
  [ADR 006](docs/adr/006-interim-bearer-token-auth.md) states the trade-offs.
- **The audit trail is log-only.** Mutating requests are logged with the
  authenticated principal, but there is no append-only `audit_logs` table and
  no before/after values, as §15.6 requires. Tracked as T-24; the table lands
  with the entities it records changes to.
- **No containers and no DAST.** Five adapters are registered, so a repository
  scan covers secrets, an SBOM, known vulnerabilities, SAST, and
  misconfiguration. Trivy image targets and OWASP ZAP are not built, so a
  "clean" scan says nothing about a built image or a running endpoint. This is
  also why correlation serves no `image:` or `endpoint:` key.
- **The SBOM is stored but not queried.** Syft's output is persisted as a raw
  result; nothing parses it into queryable components. So "is this vulnerable
  dependency actually in the build?" is unanswerable, and neither correlation
  nor the risk engine can ask it.
- **No gate.** The score and the remediation plan exist but nothing enforces
  them: there is no PASS/WARN/FAIL evaluation and no CI integration, so
  SecureOps cannot yet fail a build. Phase 8.
- **No transitive dependency reasoning.** Whether upgrading a direct dependency
  resolves a finding in a transitive one needs the SBOM component storage that
  does not exist, so an upgrade action speaks only about the package named.
- **No single upgrade target.** An action lists every fixed version its
  findings reported and does not choose between them, because version ordering
  is ecosystem-specific and a confidently wrong target is worse than a list.
- **Shallow clones, so no git history.** A credential committed and later
  removed is not detected. History scanning is a follow-up
  ([ADR 008](docs/adr/008-repository-fetching.md)).
- **Public repositories only.** There is no git credential handling, by
  choice — per-project credential storage is real product surface, not
  something to add as a side effect.
- **Nothing can dismiss a finding yet.** The risk engine scores resolved, false
  positive, and ignored findings at zero, and the lifecycle records every
  transition, but no API endpoint performs one — only the automatic
  resolve-on-rescan can change a status today.
- **Exposure is per project, not per finding.** Whether *this* vulnerable
  package is reachable from *this* internet-facing service needs reachability
  analysis and SBOM component storage, neither of which exists. The declared
  project context is a coarse but honest proxy.
- **Risk weights are uncalibrated against real projects.** They are
  configuration, with the reasoning for every constant written down, so they
  can be corrected by evidence rather than argument.
- `.grype.yaml` suppresses six CVEs in golang-migrate's Docker-based test
  drivers. They are not linked into any binary (`go version -m` reports zero).
  Rules are scoped to specific vulnerability IDs, so a new CVE in those modules
  still fails the build. Reasoning in
  [ADR 005](docs/adr/005-keep-golang-migrate.md).
- Scanner binaries are not provenance-verified (threat model T-10).
- Corroboration between scanners counts distinct names, not distinct evidence:
  Grype and Trivy read overlapping advisory feeds, so their agreement is weaker
  than it looks. Bounded by capping the raise at one step, and recorded in
  [docs/architecture/risk-engine.md](docs/architecture/risk-engine.md).

## License

[MIT](LICENSE)
