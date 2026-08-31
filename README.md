# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phase 3 in progress — SecureOps now runs a real scan end to end.**

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
| 3b | Remaining adapters: Grype → Semgrep → Trivy → ZAP | next |
| 4–14 | Normalization, correlation, risk, remediation, policy, dashboard, CI/CD, hardening, Kubernetes, observability | not started |

Phase 2 added the `Scanner` interface with capability-driven selection, a
validated `Target` model (SSRF, path traversal, and argument-injection
defences), argv-only subprocess execution with resource limits, ephemeral
per-job workspaces, the scan lifecycle with `PARTIAL` semantics, a Redis job
queue, and the worker binary. It built the machinery, but nothing could drive
it: no endpoint created a scan.

The scan API closes that gap. `POST /api/v1/scans` returns **202** with a scan
id and enqueues the work; the request never blocks on scanner execution.
Projects can be created and listed, scan history is queryable, and a failed
scan now records *why* it failed instead of reporting a bare `failed`.

It also closes the project's largest open security gap. Every `/api/v1`
endpoint except health now requires a bearer token — shipping write endpoints
with no authentication was not an option, and waiting for Phase 11's full RBAC
would have meant doing exactly that. The gate is deliberately interim; see
[ADR 006](docs/adr/006-interim-bearer-token-auth.md) for what it does and does
not buy.

The first adapter works. Submit a repository and the worker clones it into an
ephemeral workspace, runs Gitleaks against the checkout, and records what it
found — verified against a public repository of planted secrets: 22 detected,
locations and rules retained, **zero credentials persisted**.

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

**Two scanners are registered: Gitleaks and Syft.** A repository scan today
means secret scanning plus an SBOM — no SAST, no known-vulnerability matching,
no containers. Adding an adapter is one line in
[cmd/worker/main.go](cmd/worker/main.go) plus its own package.

Normalization, correlation, risk scoring, remediation, and security gates are
**not implemented**. See
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

Until adapters land, that poll returns `"status": "failed"` with
`"failure_reason": "no registered scanner supports this target kind"`. The
queue, the worker, and the persistence are all real; only the adapters are
missing.

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
- [Architecture decision records](docs/adr/) — Go backend, PostgreSQL, Redis,
  [scanner isolation](docs/adr/004-scanner-isolation.md),
  [keeping golang-migrate](docs/adr/005-keep-golang-migrate.md),
  [interim bearer-token auth](docs/adr/006-interim-bearer-token-auth.md),
  [secret redaction](docs/adr/007-secret-redaction-in-raw-results.md),
  [repository fetching](docs/adr/008-repository-fetching.md), and
  [building scanners from source](docs/adr/009-build-scanners-from-source.md)

### Security documentation

- [Threat model](docs/security/threat-model.md) — 30 threats per trust
  boundary, each labelled mitigated, partial, or open, with the test that
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
- **Two scanners.** Gitleaks covers secrets, Syft produces the SBOM. SAST,
  known-vulnerability matching, containers, IaC, and DAST have no adapter yet,
  so a "clean" scan today means only that no secrets were found.
- **The SBOM is stored but not yet queried.** Nothing matches it against
  vulnerability data — that is Grype, next — and there is no `sboms` table or
  API surface for it until Phase 4.
- **Shallow clones, so no git history.** A credential committed and later
  removed is not detected. History scanning is a follow-up
  ([ADR 008](docs/adr/008-repository-fetching.md)).
- **Public repositories only.** There is no git credential handling, by
  choice — per-project credential storage is real product surface, not
  something to add as a side effect.
- **Findings are not normalized yet.** Raw scanner output is stored and the
  per-scanner status is reported, but the canonical `Finding` model,
  fingerprinting, correlation, and risk scoring are Phases 4-6. There is no
  finding list in the API.
- `.grype.yaml` suppresses six CVEs in golang-migrate's Docker-based test
  drivers. They are not linked into any binary (`go version -m` reports zero).
  Rules are scoped to specific vulnerability IDs, so a new CVE in those modules
  still fails the build. Reasoning in
  [ADR 005](docs/adr/005-keep-golang-migrate.md).
- Scanner binaries are not provenance-verified (threat model T-10).
- `docs/architecture/` is empty. The fingerprint strategy and risk formula must
  be documented there before their implementation, in Phases 4 and 6.

## License

[MIT](LICENSE)
