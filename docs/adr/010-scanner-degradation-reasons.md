# ADR 010: Scanner degradation is an explainable reason, not a status

- **Status:** Accepted
- **Date:** 2026-09-01
- **Supersedes:** nothing. Generalizes a mechanism introduced in Phase 2.

## Context

A scan must never report clean coverage it did not have (CLAUDE.md §13). Today
`ScannerResult` expresses that with a single boolean:

```go
Truncated bool

func (r ScannerResult) Succeeded() bool {
    return r.Status == ScannerSucceeded && !r.Truncated
}
```

That works, and truncation is handled correctly: a truncated result is not
`Succeeded()`, so `TerminalStatus()` returns `PARTIAL` and
`HasCompleteCoverage()` returns false.

The mechanism does not generalize, and the next adapter proves it. Grype
carries a local vulnerability database and reports its build date in every
report (`descriptor.db.status.built`, plus a `valid` flag and per-provider
`captured` timestamps).

Grype does guard against staleness, and it is worth being exact about how,
because the shape of that guard is the argument. `db.validate-age` defaults to
true with a `max-allowed-built-age` of five days, and a database older than that
makes grype **exit 1**. Measured, not assumed: forcing the age limit to one
second fails the scan, and disabling the check produces a full report from the
same database.

So grype offers two behaviours and neither is the one this project needs.
Failing discards findings that are real — they are an under-count, not fiction —
and trains operators to ignore failures. Passing reports fewer vulnerabilities
than exist with no signal at all: a **false clean**, which reaching a security
gate is worse than having no gate.

That second case is not hypothetical for us. An air-gapped worker, or one whose
database refresh failed, is exactly the deployment that disables the age check —
and SecureOps will disable it deliberately, for the reason above. Turning off
grype's guard is what creates the exposure, so something has to replace it.

Trivy has the same property. ZAP will have its own variants — an unauthenticated
crawl, a ruleset that failed to load.

## Decision

Replace the boolean with a set of named reasons, owned by
`internal/scanners`:

```go
type Degradation string

const DegradedOutputTruncated Degradation = "output_truncated"

func (r ScannerResult) Succeeded() bool {
    return r.Status == ScannerSucceeded && len(r.Degradations) == 0
}
```

An adapter reports degradations on its `RawResult`; the worker copies them onto
the `ScannerResult`; `Succeeded()` treats any non-empty set as incomplete
coverage, so a degraded scanner still forces `PARTIAL` exactly as truncation
does today. The persisted column is `degradations text[]`.

Reasons are added **only alongside a producer.** This ADR introduces exactly
one, `output_truncated`, because that is the only reason anything currently
emits. `stale_vulnerability_db` lands with the Grype adapter, not before.

## Alternatives considered

**A new `degraded` scanner status.** This was the original proposal and it is
worse. It would sit next to the existing `Truncated` boolean rather than
replacing it, leaving two mechanisms for one concept and no principled answer to
"is a truncated result `succeeded`+truncated, or `degraded`?". It also fails
§12: a gate must explain the exact conditions that produced its result, and
`degraded` on its own tells an operator nothing they can act on, whereas
`stale_vulnerability_db` tells them to refresh the database.

**A boolean per cause** (`truncated`, `stale_db`, ...). Each new cause becomes a
schema migration and a new term in `Succeeded()`. The set-valued column costs
nothing extra and bounds itself.

**A CHECK constraint pinning the vocabulary in SQL.** Rejected: adding a scanner
must require zero changes outside its own package (§7 rule 4), and this would
make any adapter reporting a new reason also a schema change. The column is
bounded (≤16 elements) and well-formed (no NULL or empty elements); the
vocabulary lives in Go.

**Treating a stale database as a scanner failure.** This is grype's own default
(`db.validate-age`), and it overstates the problem. The scan did run and its
findings are real — they are merely an under-count. Failing it discards genuine
results and trains operators to ignore failures. SecureOps therefore disables
grype's age check and reports staleness as a degradation instead, which keeps
both the findings and the warning.

## Consequences

- `scan_scanner_results.truncated` is dropped and backfilled into
  `degradations`. This is a non-additive schema change, approved explicitly by
  the project owner as §24 requires. The table carries no production data.
- The rollback is **lossy in one direction**: it restores `truncated` from
  `output_truncated`, but any other reason is discarded, converting explained
  degraded coverage into apparently complete coverage. Recorded in the down
  migration itself.
- The API response for a scanner result changes shape: `truncated: bool` becomes
  `degradations: string[]`. A breaking change to an unreleased endpoint, made
  visibly and with the OpenAPI spec updated in the same change, rather than
  silently (§25.17).
- Core code still never branches on a scanner's name (§7 rule 2). An adapter
  names its own reasons; `Succeeded()` only asks whether the set is empty.
- **Not addressed here:** `scan_raw_results.truncated` is a different fact — the
  archived copy of the output was clipped at the storage cap, while the adapter
  parsed the whole thing. Coverage was complete; only later re-processing would
  be degraded. It keeps its boolean.
