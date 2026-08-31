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
`captured` timestamps). A scan run against a stale database **succeeds**: exit
code 0, well-formed JSON, fewer vulnerabilities than actually exist, and no
error anywhere in the pipeline. It is a false clean, and a false clean that
reaches a security gate is worse than no gate at all.

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

**Treating a stale database as a scanner failure.** Overstates it. The scan did
run and its findings are real — they are merely an under-count. Failing it
discards genuine results and trains operators to ignore failures.

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
