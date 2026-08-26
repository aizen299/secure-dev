# SecureOps

Unified DevSecOps platform for automated source code, dependency, container,
secret, API, and infrastructure security assessment with vulnerability
correlation, unified risk scoring, and prioritized remediation.

> SecureOps turns fragmented security scanner output into one contextual
> security decision.

## Status

**Phase 1 of 14 — foundation.** The API skeleton, dashboard shell, database
schema, local stack, and CI are in place.

Scanner orchestration, normalization, correlation, risk scoring, remediation,
and security gates are **not implemented yet**. See
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
cmd/migrate/      migration runner
internal/         application packages
apps/web/         Next.js dashboard
migrations/       SQL migrations (forward + rollback)
deployments/      Dockerfiles
docs/             specification, ADRs, architecture, security
```

## Documentation

- [CLAUDE.md](CLAUDE.md) — architecture and engineering rules
- [Specification](docs/SecureOps_Claude_Code_Project_Specification.md)
- [Architecture decision records](docs/adr/)

## License

[MIT](LICENSE)
