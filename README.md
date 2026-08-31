# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phase 3 in progress — the scan API is live; scanner adapters are next.**

Phase 3 is split into 3a and 3b below. The specification's phase list names only
the adapters, so the scan API is recorded as its own step rather than folded
silently into a phase that did not describe it; see [CLAUDE.md](CLAUDE.md) §26.

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3a | Scan API and interim authentication | done |
| 3b | Scanner adapters: Gitleaks → Semgrep → Syft → Grype → Trivy → ZAP | next |
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

**No scanner adapters are registered yet**, so a submitted scan is accepted,
queued, picked up by a worker, and then fails with `failure_reason: "no
registered scanner supports this target kind"`. That is expected until adapters
land — `registerScanners` in [cmd/worker/main.go](cmd/worker/main.go) is empty
until then. The pipeline around it is real and exercised end to end.

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
  scans/          scan lifecycle and persistence
  queue/          scan job queue (Redis, plus in-memory for tests)
  worker/         job runner: concurrency, timeouts, failure isolation
  netguard/       SSRF address policy
  auth/           interim bearer-token verification (ADR 006)
  projects/       project entity, validation, persistence
  httpapi/        routing, middleware, auth gate, handlers, health
  config/ logging/ storage/
apps/web/         Next.js dashboard
migrations/       SQL migrations (forward + rollback)
deployments/      Dockerfiles
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
  [keeping golang-migrate](docs/adr/005-keep-golang-migrate.md), and
  [interim bearer-token auth](docs/adr/006-interim-bearer-token-auth.md)

### Security documentation

- [Threat model](docs/security/threat-model.md) — 24 threats per trust
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
- **No scanner adapters.** Every submitted scan fails by design until Phase 3
  registers them.
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
