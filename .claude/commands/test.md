---
description: Run the full SecureOps test and lint suite, reporting honestly
---

Run the project's validation suite and report exactly what happened.

1. `make check` — gofmt, go vet, golangci-lint, Go tests with `-race`, web lint
   and type-check.
2. If PostgreSQL and Redis are running (`docker compose ps`), also run
   `make test-integration`. If they are not, say so and report integration tests
   as **skipped** — never as passed.

Report: which steps ran, which passed, which failed with their output, and
which were skipped and why. A skipped step is never reported as a pass
(CLAUDE.md §23).

Do not weaken a test or a security control to get a green result. If something
fails, fix the code or report the failure.
