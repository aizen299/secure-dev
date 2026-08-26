# ADR 001: Go with Chi for the backend

- **Status:** Accepted
- **Date:** 2026-08-26

## Context

SecureOps orchestrates external scanner processes, runs concurrent jobs, and
exposes a REST API. The backend owns the API layer, authentication, scan
orchestration, job management, persistence, and the normalization, correlation,
risk, remediation, and policy engines.

Two properties dominate the choice. First, the workload is heavily concurrent:
many scans, each fanning out to several scanner processes. Second, the platform
must invoke subprocesses without a shell, because it handles attacker-controlled
input (CLAUDE.md §14.4).

## Decision

Use **Go** with the **Chi** router.

Chi is a thin router over `net/http`. It adds routing and middleware
composition without introducing its own request/response abstractions, so
handlers remain standard `http.Handler` values and stay testable with
`net/http/httptest`.

## Alternatives considered

- **Gin** — more batteries included, but it wraps `net/http` in its own context
  type, which couples handlers to the framework. The specification lists Chi
  first and Chi's smaller surface suits a security product.
- **Python (FastAPI)** — much security tooling is written in Python, which is
  the tempting reason to adopt it. It is not a sufficient one: SecureOps
  *invokes* those tools as subprocesses and never imports them. Python would add
  a GIL-bound concurrency story and a heavier runtime for no gain. The
  specification explicitly rejects this.
- **Node/TypeScript for both tiers** — would unify the language with the
  dashboard, but the backend is process-orchestration heavy, where Go's
  `os/exec` and context-based cancellation are a much better fit.

## Consequences

- `exec.CommandContext` gives argument-vector execution and context-driven
  timeouts and cancellation — exactly the primitives §14 demands. No shell is
  ever involved.
- Static binaries build into minimal distroless images that run as non-root.
- Two languages in the repository (Go, TypeScript). Accepted: the tiers have
  genuinely different jobs, and the API contract is the boundary between them.
- Goroutine-per-job concurrency makes worker pools and per-scan limits natural.
