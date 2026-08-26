---
description: Run a SecureOps scan against a target and report the result
---

Run a scan through the platform and report what came back.

**Preconditions.** Check these first and report honestly if unmet:

- Is the stack running? (`docker compose ps` — postgres, redis, api, worker)
- Are any scanner adapters registered? Until Phase 3 lands adapters,
  `registerScanners` in `cmd/worker/main.go` is empty and **every job fails by
  design**. Say so rather than presenting the failure as a bug.
- Is there a scan submission endpoint yet? Until one exists, scans can only be
  exercised through `make test-integration`.

**Running a scan.** Once the API supports it, submit the target, confirm the
response is **202 Accepted** with a scan ID, then poll `GET /scans/{id}`. Never
hold a request open waiting for scanners (§13).

**Reporting.** Give the scan status, the per-scanner outcome, and the reason for
any that failed or were skipped. A `PARTIAL` scan means degraded coverage —
report it as such, never as a clean result (§13). A missing scanner binary is
`skipped`, which is absent coverage, not a passing scan.
