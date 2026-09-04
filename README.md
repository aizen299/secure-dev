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
scored, turned into ranked work, and judged against a per-project policy. The
pipeline in CLAUDE.md §3 is complete end to end; what is missing is the CI
plumbing that carries the verdict into a pull request (Phase 10).

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
| 3b | **Trivy image targets** (public registries) | done |
| 3b | **ZAP** adapter (DAST, passive only) | done |
| 4 | **Normalization**: canonical Finding, fingerprinting, deduplication | done |
| 4 | **Findings persistence**: lifecycle across scans, API | done |
| 5 | **Correlation**: contextual issues, cross-domain links, severity escalation | done |
| 6 | **Threat intelligence**: EPSS capture with provenance | done |
| 6 | **Risk engine**: contextual scoring, max-dominant aggregation | done |
| 7 | **Remediation**: vendor fix facts, consolidated actions, ranking | done |
| 8 | **Policy engine**: PASS/WARN/FAIL gates, durable audit log | done |
| 9 | **Dashboard**: security posture, findings triage, gate, remediation | done |
| 10–14 | CI/CD integration, hardening, Kubernetes, observability | not started |

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

This is where **container images** earn their place. Point a scan at
`ghcr.io/org/api:1.2.3` and Trivy reports what is installed in it — not what a
lock file declares, which it deliberately ignores. So when Grype finds a CVE in
a dependency the repository declares and Trivy finds that same component
installed in the image, the two meet on one component key and the issue is
escalated: a vulnerability that is *deployed* is worse than one that is merely
*declared*.

That the two meet at all is measured rather than assumed. Both scanners emit
`pkg:npm/express@4.17.1` byte for byte, and
`TestRepositoryAndImageFindingsCorrelate` runs the real captured output of both
through the mappers and the engine to prove it.

A finding's identity uses the image **repository**, never the tag or digest —
otherwise every rebuild would resolve every finding and open an identical set of
new ones. There is deliberately no `image:` correlation key: every finding in an
image shares it, which makes it a filter rather than a relationship, so it is an
indexed column instead. [ADR 025](docs/adr/025-container-image-targets.md) has
the reasoning.

**Dynamic testing** adds the fourth kind of target: a running application.
Point a scan at a deployed URL and ZAP crawls it and reports what its passive
rules see. It does **not** attack the target — the `activeScan` job is absent
from the plan rather than disabled in it, because a payload delivered to a real
form submits that form, and whether that is authorized is a fact about who owns
the host rather than a flag on a scan.

A DAST finding's identity is its rule and the URL **path** — never the origin,
for the same reason a container finding's identity is never the tag. A CI
preview environment mints a hostname per pull request, and an origin in the
identity would reopen every finding on every PR.

The query string is dropped too, which serves two purposes at once: it is
per-request noise, and it is where an application carries credentials. That is
measured, not assumed — a target serving one link to `/search?api_key=…` put
that key in seven places in a single ZAP report, so the report is rewritten
before anything is stored. See
[ADR 026](docs/adr/026-dast-passive-only.md).

ZAP ships in the worker image, and runs from its jar rather than through its
launcher script — the launcher is bash, and the container that executes
untrusted content does not ship a general-purpose shell. Only the nine add-ons
the scan plan uses are installed; the 41 left out include `ascanrules`, ZAP's
active scan rules, so the payloads are absent from the image as well as from the
plan. Running from the jar also means the JVM heap ceiling is set explicitly
rather than guessed from host memory, which makes it a declared limit. See
[ADR 030](docs/adr/030-zap-in-the-worker-image.md).

Read the issues at `GET /api/v1/projects/{id}/issues`. The rules, the escalation
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

Finally, a decision: **may this ship?**

A policy is a set of rules a team chooses — no criticals, at most five highs, no
exposed secrets, risk below 70 — each configured to `warn` or `fail` on its own.
The verdict is the worst level breached. Rules are data, so the same rule blocks
one team's build and merely warns another's, and the vocabulary is the canonical
model's own: a policy says "no critical findings", never "no Gitleaks findings".

**An incomplete scan can never pass.** This is the failure the whole coverage
chain exists to prevent: a scanner crashes, reports nothing, fewer findings
breach fewer rules, and a broken scan sails through the gate *because* it broke.
A scan that is not `completed` produces at least a warning, and `pass` is not a
value the schema will store for one.

Every rule is reported, breached or not — including on a pass. A result listing
only its breaches makes "the project is clean" and "the policy checks nothing"
look identical, which is the bare verdict §12 forbids wearing a friendlier face.
The same conditions render as machine-readable JSON for CI and as prose for a
pull-request comment, so the two cannot disagree.

Changing a policy is the most security-sensitive write in the API — raising the
critical limit from 0 to 50 turns the gate off — so every change is recorded in
an **append-only audit log**, written in the same database transaction as the
change itself. A record that could be lost while the change survived would leave
gaps that look exactly like inaction. `audit.Write` takes a transaction and not
a connection pool, so passing the wrong thing is a compile error rather than a
hole that only appears when a commit fails.

And it requires an **admin** token. Tokens carry a role — `viewer`, `service`,
`admin` — so the credential CI uses to submit scans cannot switch off the gate
judging it, which was the realistic path from an over-shared secret to a
silently disabled control (ADR 023).

That is authorization in the narrow sense only. There is no tenancy: an admin
token can edit *any* project's policy, and a static token labels a client rather
than a person. T-23 is narrowed, not closed.

Read the gate at `GET /api/v1/scans/{id}/gate` and the policy at
`GET /api/v1/projects/{id}/policy`. The rule model and what the engine refuses
to do are in [docs/architecture/policy.md](docs/architecture/policy.md),
[ADR 021](docs/adr/021-policy-evaluation-and-gates.md), and
[ADR 022](docs/adr/022-durable-audit-log.md).

And a finding can be **judged**. A person may acknowledge one, start work on it,
dismiss it as a false positive, accept it as a known risk, or reopen a dismissal
they later disagree with — because a gate that fails on a false positive nobody
can dismiss is a gate teams route around, and routing around it disables the
control for everything else too.

What a person may **not** do is mark a finding `resolved`. That state means *a
scanner stopped reporting this*, and a hand-typed one would be indistinguishable
afterwards from a verified one while dropping the risk score and turning a gate
green with nothing repaired. A fix no scanner can see is recorded as `ignored`
with a note saying why — the same decision, without a verification claim nobody
earned.

Every judgement records who, when, why from a fixed vocabulary, and the argument
behind it, written in the same transaction as the change. Read a finding's whole
history at `GET /api/v1/findings/{id}/history`, where scan-driven transitions sit
alongside human ones attributed to `system`. The rules are in
[ADR 024](docs/adr/024-human-finding-transitions.md).

**Five scanners are registered: Gitleaks, Syft, Grype, Semgrep, and Trivy.** A
repository scan today means secret scanning, an SBOM, known-vulnerability
matching, static analysis, and misconfiguration — no container images, no DAST.
Adding an adapter is one line in [cmd/worker/main.go](cmd/worker/main.go) plus
its own package.

CI/CD integration is **not implemented**. See
[the specification](docs/SecureOps_Claude_Code_Project_Specification.md) for the
full plan and [CLAUDE.md](CLAUDE.md) §26 for the phase breakdown.

## The dashboard

The dashboard is where Phases 4 through 8 become visible. It reads the same API
a CI client does, and it shows the things the engines actually produce: the risk
score and its trend, the severity distribution behind it, the gate verdict with
every condition that produced it, the correlated issues, and the remediation
plan ranked by risk removed.

**Scanning is pasting a URL.** Sign in, choose **Repository** or **Website**,
paste an `https://` URL, and the dashboard creates the project if it does not
exist, queues the scan, and follows it to the result. The slug is derived from
the URL, so pasting the same target twice adds to its history rather than
starting a second project beside it.

The kind is chosen rather than inferred. `.git means repository` and
`github.com means repository` both look reasonable and are wrong often enough to
matter — a heuristic would clone a website or crawl a repository host, and the
failure would read as the platform being broken. **Website** runs passive DAST
only: it crawls, reports what its passive rules see, sends no attack payloads,
and signs in to nothing.

Four properties are worth stating because they are decisions rather than
styling.

**It authenticates, and one password is not a user model.** A shared password
(`SECUREOPS_DASHBOARD_PASSWORD`) is exchanged for an HMAC-signed session cookie.
That answers "may this browser look at this?" and deliberately not "who is
looking?" — per-user identity is Phase 11. The signature is verified
server-side on every page and route handler; the middleware only checks that a
cookie is present, because the edge runtime has no `node:crypto` and a partial
check there would invite the belief that it is the boundary.

**It can queue a scan, and still cannot judge one.** Since
[ADR 029](docs/adr/029-dashboard-authentication.md) it holds a `service`
credential rather than a `viewer` one — enough to create projects and scans,
and deliberately not `admin`, so it cannot edit the policy that judges them. It
still cannot dismiss a finding. And the audit trail records the dashboard's own
credential, not a person: the session knows a browser authenticated, not who,
and a client that asserts its own identity in an audit record makes that record
worthless.

**The credential never reaches the browser.** Every read happens in a Server
Component or a route handler, and the API client is marked `server-only`, so a
client component that imports it fails the build rather than shipping a token.
The browser talks to the dashboard; the dashboard talks to the API.

**Absence is rendered as absence.** "No credential", "no data", and
"unreachable" are three different screens, because collapsing them is how an
operator learns to distrust a dashboard. A finding with no EPSS signal shows a
dash, never `0%` — nobody measured it, and that is not the same as unlikely.

It also does not compute anything the engines did not. The obvious aggregate —
"the score if every remediation action were taken" — is deliberately absent:
`score_after` is per action, the aggregation is max-dominant, and the combined
effect is not the sum. See
[ADR 027](docs/adr/027-dashboard-data-access.md).

```bash
SECUREOPS_API_TOKEN=<secret> SECUREOPS_DASHBOARD_PASSWORD=<password> \
  npm --prefix apps/web run dev
```

The token is the *secret* alone — the third field of a `label:role:secret` entry
in the API's `SECUREOPS_API_TOKENS`, not the whole triple. With no password set
nobody can sign in; that is the intended failure mode, not a bug to work around.

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

The dashboard needs its own credential or it will start and tell you it has
none. Add a `service` token to `SECUREOPS_API_TOKENS`, then point
`SECUREOPS_DASHBOARD_TOKEN` at that token's **secret** — the third field of
`label:role:secret`, not the whole triple — and set a login password:

```text
SECUREOPS_API_TOKENS=dashboard:service:<secret>,ci:service:<other-secret>
SECUREOPS_DASHBOARD_TOKEN=<secret>
SECUREOPS_DASHBOARD_PASSWORD=<the password you will type at the login screen>
SECUREOPS_DASHBOARD_SESSION_KEY=<32+ random bytes, hex>
```

`SECUREOPS_DASHBOARD_SESSION_KEY` may be omitted, in which case one is
generated per process and every restart signs you out. Set it for anything
that is not a single local container.

The session cookie is marked `Secure` in a production build. Browsers treat
`localhost` as a trustworthy origin, so `http://localhost:3000` works; a
deployment reached over plain HTTP at any other address will not store the
cookie, and login will appear to loop. Serve it over HTTPS. The cookie is not
downgraded to make that case work — a session for a security tool travelling in
clear text is the thing the flag exists to prevent.

The role changed from `viewer` to `service` in ADR 029, because the URL bar
submits scans. A `viewer` secret still works if you want the ADR 027 read-only
posture; the URL bar then surfaces the API's own 403 rather than failing
quietly.

The secret never reaches the browser — every read happens in a Server
Component or a route handler and the API client is marked `server-only`
(ADR 027). `make up` rebuilds the images — a dashboard serving an older build
is the most likely reason a screen looks out of date.

**Upgrading from a `.env` written before token roles.** ADR 023 changed
`SECUREOPS_API_TOKENS` from `label:secret` to `label:role:secret`. The API
refuses to start on the old form rather than assume a role, so the first
symptom is an API container in a restart loop and everything downstream
reporting the API as unreachable:

```text
auth: token 1 is not in label:role:secret form (roles are viewer, service, admin)
```

A container built before that change keeps running on its old binary, so the
mismatch only appears on the next rebuild. Add the role a token already had in
practice — `admin` for a pre-roles token, which is exactly the power it held
when roles did not exist — and give the dashboard its own `viewer` entry.
`docker compose logs api --tail=3` names the offending token by position.

The API is published on **8090**, not 8080. Go binds `":8080"` as the
dual-stack wildcard, which succeeds even when another process already holds
`127.0.0.1:8080` — the two sockets do not collide. The result is split-brain
routing where `localhost:8080` and `127.0.0.1:8080` reach different servers,
and nothing fails loudly. `.env.example` explains which of the three port
settings does what.

## Using the API

Every `/api/v1` endpoint except health requires a bearer token. Tokens are
`label:role:secret` triples, and the API refuses to start without at least one.

Roles are `viewer` (reads only), `service` (submits scans, creates projects),
and `admin` (additionally edits security policy). Give CI a `service` token: it
is the most widely distributed credential you have, and it must not be able to
switch off the gate that judges it (ADR 023).

```bash
echo "SECUREOPS_API_TOKENS=local-admin:admin:$(openssl rand -hex 32),ci:service:$(openssl rand -hex 32)" >> .env
```

An un-roled `label:secret` pair now fails at startup rather than being treated
as anything — a permissive default is what a credential gate exists to refuse.

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
    trivy/        IaC and config (ADR 015 line redaction); container image
                  vulnerabilities from public registries (ADR 025)
    zap/          DAST against a running application; passive only,
                  with the ADR 026 redaction control
  normalization/  raw output -> canonical Finding, fingerprinting, dedup (pure)
  correlation/    contextual issues, cross-domain links (pure)
  risk/           deterministic contextual scoring (pure)
  remediation/    consolidated actions, ranked by risk removed (pure)
  policies/       gate rules, PASS/WARN/FAIL, policy persistence
  audit/          append-only audit records, atomic with the change
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
  [remediation](docs/architecture/remediation.md), and
  [the policy gate](docs/architecture/policy.md)
- [Architecture decision records](docs/adr/) — thirty, written before the
  decisions they record. The ones that most shape the system:
  [scanner isolation](docs/adr/004-scanner-isolation.md),
  [secret redaction](docs/adr/007-secret-redaction-in-raw-results.md),
  [building scanners from source](docs/adr/009-build-scanners-from-source.md),
  [the API contract enforced by tests](docs/adr/011-api-contract-enforced-by-tests.md),
  [the canonical finding model](docs/adr/016-canonical-finding-model-and-fingerprint.md),
  [correlation semantics](docs/adr/017-correlation-issues-and-severity.md),
  [threat intelligence as its own attribute](docs/adr/018-threat-intelligence-is-its-own-attribute.md),
  [risk scoring](docs/adr/019-risk-scoring-and-aggregation.md),
  [remediation actions](docs/adr/020-remediation-actions-and-prioritization.md),
  [policy gates](docs/adr/021-policy-evaluation-and-gates.md),
  [the durable audit log](docs/adr/022-durable-audit-log.md),
  [token roles](docs/adr/023-token-roles.md),
  [human finding transitions](docs/adr/024-human-finding-transitions.md),
  [container image targets](docs/adr/025-container-image-targets.md),
  [passive-only DAST](docs/adr/026-dast-passive-only.md),
  [dashboard data access](docs/adr/027-dashboard-data-access.md),
  [dashboard authentication](docs/adr/029-dashboard-authentication.md),
  and [ZAP in the worker image](docs/adr/030-zap-in-the-worker-image.md)

### Security documentation

- [Threat model](docs/security/threat-model.md) — 60 threats across seven trust
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
- **DAST is passive only — SecureOps does not test for injection.** ZAP's
  active scanner sends crafted attack payloads at a live application: it writes
  to real forms, and whether that is authorized depends on who owns the target.
  The `activeScan` job is absent from the scan plan rather than disabled in it.
  What DAST covers is what passive rules see — missing headers, cookie flags,
  information disclosure, absent CSRF tokens. Active scanning needs a
  per-project authorization model and is a separate decision.
- **DAST is unauthenticated.** Workers hold no credentials (§14.7), so a scan
  reaches only what an anonymous visitor reaches.
- **Image scanning is public-registry only.** No credentials are held or passed
  (§14.7), so a private registry is out of reach. Image size and layer-expansion
  limits are also unenforced on this path: a hostile reference is a slow scan
  bounded by the execution timeout, not a contained one (T-51).
- **The SBOM is stored but not queried.** Syft's output is persisted as a raw
  result; nothing parses it into queryable components. So "is this vulnerable
  dependency actually in the build?" is unanswerable, and neither correlation
  nor the risk engine can ask it.
- **No CI integration.** The gate produces a verdict; nothing yet carries it
  into a pull request as a status check or a comment. Phase 10.
- **No tenancy.** Tokens carry a role, so a `service` credential cannot edit a
  policy — but `admin` is global: one project's administrator can edit another
  project's gate. A role is not an identity, and a static token labels a client
  rather than a person. T-23 is narrowed, not closed; Phase 11 owns the model
  §15.5 describes.
- **The audit trail names a token, not a person.** Every security-sensitive
  action is recorded durably, but the actor is a credential's label — the
  interim token identifies a client, and recording it as a user would claim an
  attribution the authentication model cannot support.
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
- **No approval step on a dismissal.** One `service` credential can dismiss a
  finding, and nobody countersigns. Every dismissal is audited, attributed, and
  reversible, but detection is not prevention — and there is no expiry, so an
  `ignored` finding stays ignored until somebody reopens it.
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
