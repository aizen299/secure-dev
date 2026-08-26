# ADR 004: Scanner abstraction and isolation model

- **Status:** Accepted
- **Date:** 2026-08-26

## Context

SecureOps runs third-party security tools against repositories, images, and
endpoints that it does not control. A scanned repository can contain a malicious
Dockerfile, a package manifest with a hostile postinstall hook, a zip bomb, or a
path designed to escape a workspace. The scanner binaries themselves are also
untrusted in the sense that matters here: their output is attacker-influenced.

Two questions had to be settled before any adapter is written, because both are
expensive to retrofit:

1. What is the contract between the platform and a scanner?
2. What is the blast radius when a scan goes wrong?

## Decision

**A three-method interface, with capabilities for selection.**

```go
type Scanner interface {
    Name() string
    Capabilities() Capabilities
    Version(ctx) (string, error)
    Scan(ctx, target Target) (RawResult, error)
}
```

Selection is capability-driven: the platform asks "which scanners support this
target kind?", never "is this trivy?". `Capabilities` carries the supported
target kinds, the security domain, and whether the adapter needs network egress.
This is the mechanism that makes the no-scanner-conditionals rule (§7 rule 2)
enforceable rather than merely aspirational — there is no name to branch on in
the selection path.

Adapters are registered explicitly from `cmd/worker`, not through package `init`
side effects, so the wiring is visible in one place and testable.

**Isolation is layered, and each layer assumes the one above it failed.**

| Layer | Control |
|---|---|
| Input | Allow-list validation of every target; leading-dash values rejected |
| Network | SSRF policy on resolution *and* at dial time |
| Process | `exec.CommandContext` with an argv, never a shell |
| Environment | Explicit env allow-list; the parent environment is never inherited |
| Filesystem | Ephemeral per-job workspace, `0700`, destroyed on completion |
| Resource | Per-scanner timeout, output cap that kills the process, job timeout, concurrency cap |
| Process tree | Child runs in its own process group; the whole group is killed |
| Container | Non-root, read-only rootfs, all capabilities dropped, tmpfs workspace |
| Failure | Any scanner failure degrades one result; the scan and worker survive |

Two of these deserve their reasoning recorded, because both are easy to get
subtly wrong:

*Argument injection, not just command injection.* Avoiding a shell is necessary
but not sufficient. A ref of `--upload-pack=...` is a single argv element with no
shell metacharacters in it, and git will still read it as a flag. Target values
are therefore rejected when they begin with `-`.

*The output cap must terminate the process.* An implementation that merely
discards excess output lets a scanner emitting infinite data run until its
timeout, turning a size-limit breach into a slow resource drain. The cap
cancels the run context on first overflow.

## Alternatives considered

- **A richer interface** (`Parse`, `Normalize`, `Remediate` on the adapter) —
  rejected. Normalization must be a pure function over raw bytes so it is
  fixture-testable without executing a scanner (§19), and correlation must see
  canonical findings only. Keeping the adapter to "run the tool, return bytes"
  preserves that boundary.
- **Registration via `init()`** — conventional in Go, but it hides the wiring
  and makes it impossible to build a registry with a subset of adapters in a
  test. Explicit registration costs one line and is worth it.
- **Kubernetes Jobs for isolation now** — this is the stronger boundary and is
  where Phase 12 goes. Adopting it in Phase 2 would violate §25.13 (do not start
  with Kubernetes before the application runs locally) and would put a cluster
  between a developer and their first scan.
- **Running scanners in per-job Docker containers from the worker** — requires
  handing the worker a Docker socket, which is a trivially escapable root
  equivalent. Rejected outright.
- **Trusting enqueue-time validation** — rejected. The worker re-validates every
  target on arrival: the payload crossed a trust boundary, and a target that was
  safe at enqueue time may resolve differently now (DNS rebinding).

## Consequences

- Adding a scanner touches its own package plus one registration line. There is
  a test (`TestNewScannerIsSelectedWithoutCoreChanges`) that fails if selection
  ever needs to know about a specific adapter.
- Every adapter must call `scanners.Run` rather than reaching for `os/exec`, so
  the execution guarantees hold in one audited place. `gosec`'s G204 is
  annotated there, once, with justification — concentrating the pattern is what
  lets every other package stay clean.
- A missing scanner binary is `skipped`, not `failed`. Absent coverage and
  broken coverage need different operator responses, and conflating them would
  let a scan look healthy while a domain went unscanned.
- Truncated output counts as *not* succeeded, so it degrades the scan to
  `PARTIAL`. Partial evidence must never produce a clean gate result.
- DNS rebinding is mitigated but not eliminated: the dial-time `Control` hook
  guards connections SecureOps makes itself. A scanner subprocess doing its own
  DNS is outside that guard, which is one more reason network egress belongs to
  the container/network-policy layer in Phase 12.
