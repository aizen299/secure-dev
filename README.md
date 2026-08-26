# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phase 2 of 14 complete — scanner abstraction.**

| Phase | Scope | State |
|---|---|---|
| 1 | Foundation: API, dashboard shell, PostgreSQL, Redis, Compose, CI | done |
| 2 | Scanner abstraction, target validation, scan lifecycle, worker | done |
| 3 | Scanner adapters: Gitleaks → Semgrep → Syft → Grype → Trivy → ZAP | next |
| 4–14 | Normalization, correlation, risk, remediation, policy, dashboard, CI/CD, hardening, Kubernetes, observability | not started |

What Phase 2 added: the `Scanner` interface with capability-driven selection, a
validated `Target` model (SSRF, path traversal, and argument-injection
defences), argv-only subprocess execution with resource limits, ephemeral
per-job workspaces, the scan lifecycle with `PARTIAL` semantics, a Redis job
queue, and the worker binary.

**No scanner adapters are registered yet**, so submitted jobs currently fail by
design — `registerScanners` in [cmd/worker/main.go](cmd/worker/main.go) is
empty until Phase 3. There is also no `POST /scans` endpoint yet; scans are
exercised through the integration tests.

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
- API liveness: <http://localhost:8080/healthz>
- API readiness: <http://localhost:8080/readyz>

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
  httpapi/        routing, middleware, health
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
  [scanner isolation](docs/adr/004-scanner-isolation.md), and
  [keeping golang-migrate](docs/adr/005-keep-golang-migrate.md)

### Security documentation

- [Threat model](docs/security/threat-model.md) — 22 threats per trust
  boundary, each labelled mitigated, partial, or open, with the test that
  enforces it
- [Security model](docs/security/security-model.md) — assets, adversaries, and
  which controls actually exist today
- [Trust boundaries](docs/security/trust-boundaries.md)

### Known limitations

- **No authentication or authorization.** Every endpoint is currently public.
  Tracked as T-11 in the threat model; Phase 11 addresses it. The API is
  read-only today and compose binds to loopback, but that is circumstance, not
  a control.
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
