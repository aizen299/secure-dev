# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phases 1–9 and 11 are complete.** Point SecureOps at a repository, a container
image, or a running website and it returns one contextual risk score, a ranked
list of what to fix, and a PASS/WARN/FAIL verdict — with every number traceable
to the finding that produced it.

Six adapters run in isolated workers. Their output is normalized into one
canonical finding model, deduplicated, correlated into contextual issues,
scored, turned into ranked actions, and judged against a per-project policy.
The pipeline in [CLAUDE.md](CLAUDE.md) §3 is complete end to end.

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3a | Scan API and interim authentication | done |
| 3b | Repository fetching; Gitleaks, Syft, Grype, Semgrep, Trivy, ZAP adapters | done |
| 4 | Normalization, fingerprinting, deduplication, findings persistence | done |
| 5 | Correlation: contextual issues, cross-domain links, severity escalation | done |
| 6 | Threat intelligence (EPSS) and the contextual risk engine | done |
| 7 | Remediation: vendor fix facts, consolidated actions, ranking | done |
| 8 | Policy engine: PASS/WARN/FAIL gates, durable audit log | done |
| 9 | Dashboard: posture, findings triage, gate, remediation | done |
| 11 | Identity: accounts, roles, project scoping, user administration | done |
| 10 | CI/CD integration | not started |
| 12 | Kubernetes | not started |
| 14 | Final hardening and documentation | not started |
| ~~13~~ | ~~Observability~~ | dropped ([ADR 034](docs/adr/034-no-observability-phase.md)) |

Phase 3 is split into 3a and 3b because the specification's phase list names
only the adapters; the scan API is recorded as its own step rather than folded
silently into a phase that did not describe it. Phase 11 ran before 10 because
CI needs a credential that can be scoped, and scoping is Phase 11's work. Both
deviations are explained in [CLAUDE.md](CLAUDE.md) §26.

**What is missing is the CI plumbing that carries a verdict into a pull
request.** The gate produces a machine-readable result today and nothing
consumes it. That is Phase 10.

[docs/ROADMAP.md](docs/ROADMAP.md) has the sequencing, what each remaining
phase contains, and what is deliberately *not* on the list.

## How it works

Every stage is a separate package, independently testable, and each links to the
document that specifies it. Those documents were written before the
implementations they describe.

**Scanning.** A worker clones a repository into an ephemeral workspace, or pulls
an image, or crawls a URL, and runs the adapters that support that target kind.
The API never executes untrusted content; it validates, persists, and enqueues
([ADR 004](docs/adr/004-scanner-isolation.md)).

Three adapters rewrite their own output before anything is stored, because their
findings quote the credential they found: Gitleaks
([ADR 007](docs/adr/007-secret-redaction-in-raw-results.md)), Trivy's IaC source
lines ([ADR 015](docs/adr/015-trivy-output-is-rewritten-before-storage.md)), and
ZAP's query strings ([ADR 026](docs/adr/026-dast-passive-only.md)). Each then
verifies the redaction worked and discards the result if it cannot prove it. A
tool that stores harvested secrets is the worst possible outcome for a tool
meant to prevent them.

**Normalization.** Raw output becomes findings with a stable identity that
survives re-scanning — deliberately excluding line numbers, so code moving down
a file does not restart its history. Two scanners reporting one CVE on one
package produce one finding with two sources. A finding is marked `resolved`
only when every scanner that reported it completed successfully and none saw it
again, so a degraded scan can never read as "fixed". See
[fingerprinting](docs/architecture/fingerprinting.md).

**Correlation.** Findings that share a vulnerability, a component, or a file are
one problem. An issue whose members span two security domains is rated one step
above the worst of them — a vulnerable dependency that code also misuses is
worse than either fact alone. Issues *link* findings and never replace them, and
every membership carries its evidence in prose: SecureOps does not assert a
relationship it cannot explain. See
[correlation](docs/architecture/correlation.md).

**Risk.** Each finding scores as
`SeverityWeight × Exploitability × Exposure × AssetCriticality × Confidence`,
aggregated per project as `max + 0.15 × (Σ − max)`, saturated onto 0–100. Every
factor is a multiplier around a documented neutral point, so a factor with no
data contributes exactly 1.0 and cannot quietly move a score. Aggregation is
max-dominant rather than a sum, because summation makes volume and severity
interchangeable — an earlier draft of this design scored 500 informational
findings above the worst single finding the model can express.

The engine is pure and deterministic, and **no AI or heuristic model influences
it**. Adding a finding can never lower a score, which is proved rather than
sampled. See [risk-engine](docs/architecture/risk-engine.md) and
[ADR 019](docs/adr/019-risk-scoring-and-aggregation.md).

Exploitation likelihood (EPSS) is captured with its source and model date, and
absence is `null` rather than zero: 0.073 is a real probability for a critical
vulnerability, so a zero default would be indistinguishable from real data
saying nobody is exploiting this
([ADR 018](docs/adr/018-threat-intelligence-is-its-own-attribute.md)).

**Remediation.** The unit is an action, not a finding: one `npm upgrade` closing
five findings across two scanners appears once. Actions are ranked by *risk
removed* — how far the project score actually falls if you take them, computed by
rerunning the risk engine without that action's findings, which is deliberately
not the sum of their individual risk.

Nothing is invented. An action names no version no scanner reported, and where
several versions fix several advisories it lists them rather than choosing —
picking one needs ecosystem-specific version ordering, and a comparator correct
for semver is wrong for PEP 440. Every statement carries its source: `vendor`,
`scanner`, or `derived`. See [remediation](docs/architecture/remediation.md).

**The gate.** A policy is data a team chooses — no criticals, at most five highs,
risk below 70 — each rule set to `warn` or `fail` independently, in the canonical
model's vocabulary rather than any scanner's. Every rule is reported whether
breached or not, because a result listing only breaches makes "clean" and "this
policy checks nothing" look identical.

**An incomplete scan can never pass.** A scanner crashes, reports nothing, fewer
findings breach fewer rules, and a broken scan sails through *because* it broke.
A scan that is not `completed` produces at least a warning, and `pass` is not a
value the schema will store for one. See [policy](docs/architecture/policy.md).

**Accountability.** Policy changes, project and scan creation, and finding status
changes are written to an append-only audit log in the same transaction as the
change itself — `audit.Write` takes a transaction, not a pool, so passing the
wrong thing is a compile error
([ADR 022](docs/adr/022-durable-audit-log.md)).

People sign in with accounts and the trail records who
([ADR 033](docs/adr/033-identity-roles-and-project-scoping.md)). A person may
acknowledge a finding, start work, dismiss it, or reopen a dismissal — but may
**not** mark it `resolved`. That state means a scanner stopped reporting it, and
a hand-typed one would be indistinguishable afterwards while dropping the risk
score and turning a gate green with nothing repaired
([ADR 024](docs/adr/024-human-finding-transitions.md)).

## The dashboard

The dashboard reads the same API a CI client does and shows what the engines
produce: the risk score and its trend, the severity distribution behind it, the
gate verdict with every condition, the correlated issues, and the remediation
plan ranked by risk removed.

**Scanning is pasting a URL.** Sign in, choose **Repository** or **Website**,
paste an `https://` URL, and the dashboard creates the project if needed, queues
the scan, and follows it to the result. The kind is chosen rather than inferred:
`.git means repository` looks reasonable and is wrong often enough to clone a
website or crawl a repository host.

**Your role decides what you see.** The API issues a session and the dashboard
forwards it in place of its own credential, so a viewer reads what a viewer may
read and every action is audited under your name. Administrators manage accounts
from the **Access** screen; the API refuses to demote or disable the last enabled
administrator.

**A project is archived, never deleted.** Archiving hides it from the active
list and stops it accepting new scans; its scans, findings and history stay
readable at their URLs. Archived projects have their own view — **Projects →
Archived** — and restoring one is a click from its own page.

Two lists rather than one filter, because they answer different questions: an
archived project accepts no new scans, so listing it beside projects that do
would put something you cannot act on in a list read to decide what to act on.

**The credential never reaches the browser.** Every read happens in a Server
Component or a route handler and the API client is marked `server-only`, so a
client component that imports it fails the build rather than shipping a token
([ADR 027](docs/adr/027-dashboard-data-access.md)).

**Absence is rendered as absence.** "No credential", "no data", and "unreachable"
are three different screens, because collapsing them is how an operator learns to
distrust a dashboard. A finding with no EPSS signal shows a dash, never `0%`.

## Requirements

Go 1.27+ · Node 26+ · Docker with Compose · PostgreSQL 17 · Redis 8

Security tooling for the self-scan: gitleaks, semgrep, syft, grype, trivy.
Run `make tools` to check what is present.

## Quick start

```bash
cp .env.example .env
```

Edit `.env` and replace every placeholder. `.env` is gitignored and must never be
committed. At minimum, generate the API token and the session key it names.

```bash
make up
```

Builds the images, starts PostgreSQL and Redis, applies migrations, and starts
the API and dashboard.

- Dashboard: <http://localhost:3000>
- API liveness: <http://localhost:8090/healthz>
- API readiness: <http://localhost:8090/readyz>

Create the first account. There is no sign-up page and no endpoint that works
while the users table is empty — an endpoint that mints an admin should not be
reachable from the network:

```bash
echo -n 'a-long-password' | docker compose run --rm --entrypoint /usr/local/bin/useradd api -email you@example.com -role admin
```

The password comes from stdin, never a flag: a flag is visible in `ps` and lands
in shell history. That is the only account created this way — everyone after it
is added from the dashboard's **Access** screen or `POST /api/v1/users`, both
admin-only and both audited against the administrator who made the change.

### The API is on 8090, not 8080

Go binds `":8080"` as the dual-stack wildcard, which succeeds even when another
process already holds `127.0.0.1:8080` — the two sockets do not collide. The
result is split-brain routing where `localhost:8080` and `127.0.0.1:8080` reach
different servers, and nothing fails loudly. `.env.example` explains which of the
three port settings does what.

### If the API will not start

`SECUREOPS_API_TOKENS` has changed shape twice, and the API refuses the old forms
rather than guessing — a token whose role or scope cannot be determined must not
be assumed powerful. The symptom is an API container in a restart loop and
everything downstream reporting the API as unreachable. `docker compose logs api
--tail=3` names the offending token by position.

The current form is `label:role:scope:secret`. A three-field entry predates
[ADR 033](docs/adr/033-identity-roles-and-project-scoping.md); add the scope —
`*` for every project, or a comma-separated list of project slugs.

The dashboard refuses to start if `SECUREOPS_DASHBOARD_PASSWORD` is still set.
That variable was ADR 029's shared password and is gone; ignoring it would leave
you believing a credential works.

## Using the API

Every `/api/v1` endpoint except health requires a bearer token, or a session
token from `POST /api/v1/auth/login`. Tokens are `label:role:scope:secret`, and
the API refuses to start without at least one.

Roles are `viewer` (reads), `service` (submits scans, creates projects), and
`admin` (additionally edits policy and manages accounts). Give CI a `service`
token scoped to its own projects: it is the most widely distributed credential
you have, and it must not be able to switch off the gate that judges it
([ADR 023](docs/adr/023-token-roles.md)).

```bash
echo "SECUREOPS_API_TOKENS=local-admin:admin:*:$(openssl rand -hex 32)" >> .env
```

Create a project — environment, criticality, and internet exposure are risk
engine inputs, not decoration:

```bash
curl -sS -X POST http://localhost:8090/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Payments API","environment":"production","criticality":"critical","internet_facing":true}'
```

Submit a scan. Returns `202` immediately with a scan id; it does not wait for
scanners to run:

```bash
curl -sS -X POST http://localhost:8090/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"project_id":"<uuid>","target":{"kind":"repository","repository_url":"https://github.com/acme/app"}}'
```

Poll it at `GET /api/v1/scans/<uuid>`. It settles at `completed`, or at `partial`
when a scanner failed or was skipped — never a synonym for `completed`. The
per-scanner status, exit code and structured reason are all recorded.

Then read what it found. Three views of the same evidence, narrowing as you go:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/projects/<uuid>/findings
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/projects/<uuid>/issues
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8090/api/v1/projects/<uuid>/risk
```

The risk response carries more than the score. `total` is the aggregate before
saturation, which keeps separating projects after `score` flattens near 100.
`complete` says whether the score rests on a full scan — a scanner that crashed
reports nothing, and fewer findings look exactly like an improvement.
`weights_digest` identifies the configuration it was computed under, because
scores across a re-tuning are not comparable.

**A project that has never been scored returns 404, not a score of zero.** "We
have not assessed this" and "we assessed it and it is clean" are different claims.

The full contract is in [docs/api/openapi.yaml](docs/api/openapi.yaml).

## Development

```bash
make check              # format, vet, lint, Go tests with -race, OpenAPI contract, web lint/types/tests
make security           # the self-scan: gitleaks, semgrep, trivy, syft/grype
make scan-image         # scans the built container images
make test-integration   # against live PostgreSQL and Redis; run `make up` first
make help               # every target
```

Integration tests sit behind an `integration` build tag, so `go test ./...` stays
hermetic.

The dashboard's tests are narrow on purpose
([ADR 031](docs/adr/031-a-test-harness-for-the-dashboard.md)): the session
boundary, states that must agree with one another, and refusals. Nothing asserts
on spacing, colour, or animation — those break on every considered design change
and catch nothing.

`make scan-image` is deliberately not part of `make security`, which must stay
fast enough to run before every commit; CI runs it instead. It matters because
the published gitleaks binary carried 32 HIGH/CRITICAL CVEs and `trivy fs` does
not look inside images — which is why scanners are built from source
([ADR 009](docs/adr/009-build-scanners-from-source.md)).

## Architecture

```text
Next.js UI  ──►  Go API  ──┬──►  PostgreSQL   (durable domain state)
                           └──►  Redis queue  ──►  Scanner Workers (isolated)
```

The API orchestrates and never executes untrusted target content. Scanner
execution is isolated in workers. See [CLAUDE.md](CLAUDE.md) §3 and §14.

```text
cmd/api/          API server
cmd/worker/       scan worker; scanner adapters are registered here
cmd/migrate/      migration runner
cmd/useradd/      bootstrap the first admin account
internal/
  scanners/       Scanner contract, Target validation, registry, safe exec
    gitleaks/ syft/ grype/ semgrep/ trivy/ zap/
  normalization/  raw output -> canonical Finding, fingerprinting, dedup (pure)
  correlation/    contextual issues, cross-domain links (pure)
  risk/           deterministic contextual scoring (pure)
  remediation/    consolidated actions, ranked by risk removed (pure)
  policies/       gate rules, PASS/WARN/FAIL, policy persistence
  audit/          append-only audit records, atomic with the change
  findings/       findings, issues, and score persistence; lifecycle
  users/          accounts, roles, membership, sessions
  auth/           bearer-token verification, roles, project scope
  scans/ queue/ worker/ projects/ fetch/ netguard/ httpapi/
  config/ logging/ storage/
apps/web/         Next.js dashboard
migrations/       SQL migrations (forward + rollback)
deployments/      Dockerfiles
tests/            fixtures (captured scanner output, including hostile cases)
                  and integration tests against real PostgreSQL and Redis
docs/             specification, ADRs, architecture, security
```

Scanner-specific knowledge lives only under `internal/scanners/<name>/`. The
`scanners` root package holds the contract and must never import an adapter or
branch on a scanner's name.

## Documentation

- [Roadmap](docs/ROADMAP.md) — what is done, what is next, and what is
  deliberately absent from the plan
- [CLAUDE.md](CLAUDE.md) — architecture and engineering rules
- [Specification](docs/SecureOps_Claude_Code_Project_Specification.md)
- [API reference](docs/api/openapi.yaml) — OpenAPI 3.1, kept in sync with the
  handlers; an API change without a spec change is incomplete
- [Architecture](docs/architecture/) — the deterministic engines, each specified
  before it was implemented:
  [fingerprinting](docs/architecture/fingerprinting.md) ·
  [normalization](docs/architecture/normalization.md) ·
  [correlation](docs/architecture/correlation.md) ·
  [risk engine](docs/architecture/risk-engine.md) ·
  [remediation](docs/architecture/remediation.md) ·
  [policy gate](docs/architecture/policy.md)
- [Architecture decision records](docs/adr/) — thirty-four, each written before
  the decision it records
- [Threat model](docs/security/threat-model.md) — 60 threats across seven trust
  boundaries, each labelled mitigated, partial, open, or prospective, with the
  reasoning and the control ·
  [security model](docs/security/security-model.md) ·
  [trust boundaries](docs/security/trust-boundaries.md)

## Known limitations

Stated because a security tool that overstates its coverage is worse than one
that admits its edges.

**Coverage**

- **No CI integration.** The gate produces a verdict and nothing yet carries it
  into a pull request. Phase 10.
- **The SBOM is stored but not queried.** Syft's output is persisted as a raw
  result; nothing parses it into components, so correlation cannot ask whether a
  vulnerable package is actually *in* the built image.
- **No transitive dependency reasoning**, for the same reason — an upgrade action
  speaks only about the package it names.
- **No single upgrade target.** An action lists every fixed version its findings
  reported rather than choosing one; correct version ordering is
  ecosystem-specific.
- **Exposure is per project, not per finding.** Whether *this* package is
  reachable from *this* internet-facing service needs reachability analysis no
  scanner provides. The declared project context is a coarse but honest proxy.
- **Risk weights are uncalibrated against real projects.** They are configuration
  with the reasoning for every constant written down, so they can be corrected by
  evidence rather than argument.

**Scanning**

- **DAST is passive only — SecureOps does not test for injection.** ZAP's active
  scanner delivers attack payloads to a live application and writes to real
  forms; whether that is authorized is a fact about who owns the host, not a flag
  on a scan. The `activeScan` job is absent from the plan rather than disabled in
  it, and its rules are absent from the image.
- **DAST is unauthenticated**, and **image scanning is public-registry only** —
  workers hold no credentials by design (CLAUDE.md §14.7).
- **Shallow clones, so no git history.** A credential committed and later removed
  is not found. Full history would multiply clone size and time for untrusted
  input.
- **Public repositories only.** There is no git credential handling.
- **Image size is capped** by the compressed size a manifest declares; a layer
  that decompresses far larger is bounded only by the disk trivy extracts into
  (threat model T-51, closed by Phase 12).
- **Scanner binaries are not provenance-verified** (T-10, the one Open threat,
  fixed by digest-pinned images in Phase 12).
- **Corroboration counts distinct names, not distinct evidence.** Grype and Trivy
  read overlapping advisory feeds, so their agreement is weaker than it looks.
  Bounded by capping the raise at one step.

**Identity and access**

- **No self-service on an account.** Nobody can change their own password or
  name, there is no reset flow — it needs a delivery channel the product does not
  have — and a session is revocable only by disabling the person.
- **`admin` is global.** An administrator reaches every project by definition, so
  a project cannot have its own administrator who is not also everyone else's. A
  deliberate simplification for a single-team tool; the alternative is a tenancy
  model.
- **Project membership is edited through the API**, not the Access screen:
  `PATCH /api/v1/users/{id}` with a `projects` array.
- **Bearer tokens remain, for machines.** A token carries a role and a scope but
  labels a client rather than a person, has no rotation mechanism, and is
  revocable only by a restart. Overlapping tokens are supported, so rotation need
  not be a hard cutover ([ADR 006](docs/adr/006-interim-bearer-token-auth.md)).
- **No approval step on a dismissal.** One `service` credential can dismiss a
  finding and nobody countersigns. Every dismissal is audited, attributed and
  reversible, but detection is not prevention, and an `ignored` finding never
  expires.

**Suppressions**

- `.grype.yaml` suppresses six CVEs in golang-migrate's Docker-based test
  drivers. They are not linked into any binary (`go version -m` reports zero).
  Rules are scoped to specific vulnerability IDs, so a new CVE in those modules
  still fails the build ([ADR 005](docs/adr/005-keep-golang-migrate.md)).

## License

[MIT](LICENSE)
