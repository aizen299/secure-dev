# Threat Model

Threats are enumerated per trust boundary (see `trust-boundaries.md`). Each
carries an honest status:

- **Mitigated** — a control exists and a test covers it
- **Partial** — a control exists but does not cover the whole threat
- **Open** — no control yet

"Mitigated" is never claimed on the strength of an intention. Where a test
enforces the control, it is named, because a security control without a test is
a comment.

Last reviewed: 2026-08-27, after Phase 2 (scanner abstraction).

---

## Boundary 5 — Worker → untrusted target

The highest-value boundary. Everything here assumes the target is hostile.

### T-01 Command injection via target values · **Mitigated**

A crafted ref, image reference, or path reaching a shell would give arbitrary
execution as the worker.

Scanners are invoked with `exec.CommandContext` and an argument vector. There is
no shell in the path, so metacharacters are inert data. `Run` additionally
refuses a binary name containing shell syntax, so a caller cannot smuggle in a
command line.

*Tests:* `TestRunNeverInvokesAShell` fires six payloads (`;`, `$()`, backticks,
`&&`, `|`, newline) and asserts none executed.
`TestRunRejectsCommandLineAsBinaryName`.

### T-02 Argument injection · **Mitigated**

Subtler than T-01 and missed by "block shell metacharacters" filters: a ref of
`--upload-pack=...` contains no metacharacters, is a single argv element, and is
still read by git as a flag.

Target values beginning with `-` are rejected during validation.

*Test:* `TestValidateRejectsLeadingDashArguments`.

### T-03 Path traversal out of the workspace · **Mitigated**

Filesystem targets are canonicalised and containment-checked against the
workspace root. A hostile scan ID cannot steer the workspace path either — the
directory suffix is generated, and the ID is sanitised to a safe character set.

*Tests:* `TestValidateFilesystemRejectsTraversal` (six traversal shapes),
`TestWorkspaceRejectsPathInjectionInScanID`.

### T-04 SSRF via repository or endpoint URL · **Partial**

An attacker submits a target resolving to cloud metadata, a loopback admin
service, or an internal host, using SecureOps as a proxy.

Blocked at DNS resolution *and* again at dial time via a `net.Dialer` `Control`
hook, which is what survives DNS rebinding. Every resolved address must pass,
not merely one. Cloud metadata endpoints are named explicitly. Permitting
private ranges is opt-in and refused in production.

**Why partial:** the dial-time guard covers connections *SecureOps* makes. A
scanner subprocess performing its own DNS and its own connections is outside it.
Closing that fully requires network policy at the container level (Phase 12).

*Tests:* `TestValidateRepositorySSRF`, `TestValidateEndpointSSRF`,
`TestCheckHostRejectsMixedResolution`, `TestControlFunc`.

### T-05 Resource exhaustion · **Mitigated**

Zip bombs, pathological repositories, infinite scanner output.

Per-scanner timeout, job timeout, concurrency cap, and an output cap that
**terminates the process** rather than merely discarding bytes — an early
implementation only discarded, which let a scanner emitting infinite output burn
its full timeout. All limits are configurable.

*Tests:* `TestRunOutputSizeLimit` asserts both the error *and* that abort is
immediate; `TestRunTimeoutIsEnforced`; `TestConcurrencyIsBounded`.

### T-06 Credential theft by a scanner subprocess · **Mitigated**

A malicious scanner binary, or one subverted by hostile input, reads the
worker's environment for the database DSN or Redis password.

The child environment is an explicit allow-list, never inherited. A `nil` env is
forced to empty so it cannot happen by omission.

*Test:* `TestRunDoesNotLeakParentEnvironment`.

### T-07 Untrusted content outliving the scan · **Mitigated**

Ephemeral `0700` workspace removed on completion, including on failure and
cancellation. The child runs in its own process group and the group is killed,
so a leaked helper cannot hold the workspace open.

*Tests:* `TestWorkspaceIsDestroyedAfterJob`, `TestWorkspaceLifecycle`.

### T-08 Container escape · **Partial**

Non-root, read-only root filesystem, all capabilities dropped,
`no-new-privileges`, tmpfs workspace, distroless image with no shell.

**Why partial:** these are container hardening measures, not a sandbox. Stronger
isolation (ephemeral Kubernetes Jobs, seccomp, network policy) is Phase 12.

### T-09 Poisoned scanner output · **Partial**

Scanner output is attacker-influenced and is treated as untrusted input. Output
is size-capped, and truncated output is recorded as *not* succeeded so it can
never be normalized as if whole.

**Why partial:** parsing and validation of scanner output arrives with the
adapters (Phase 3) and normalization (Phase 4). Nothing parses output yet.

### T-10 Scanner binary tampering · **Open**

A compromised scanner binary on the worker runs with the worker's privileges.
Binaries are resolved via `LookPath` and their version is captured per scan, but
there is no signature or checksum verification. Pinned, digest-verified scanner
images are the intended answer (Phase 12).

---

## Boundaries 1–2 — User and UI → API

### T-11 Unauthenticated access · **Open**

**The most significant open threat.** There is no authentication or
authorization. Every endpoint is reachable by anyone who can reach the process.

Today the exposure is limited: the API is read-only (three health endpoints) and
compose binds to loopback. That is circumstance, not control.

The moment a write endpoint exists, an unauthenticated caller can drive scans.
An interim shared-secret gate lands with the first write endpoint; real
authentication and RBAC are Phase 11.

### T-12 Log-correlation poisoning · **Mitigated**

A client-supplied `X-Request-Id` is discarded and a server-generated ID used.

*Test:* `TestRequestIDIsServerGeneratedAndNotClientControlled`.

### T-13 Information disclosure through errors · **Mitigated**

Handler panics return a fixed message; the panic value and stack stay in logs.
Readiness reports a dependency as unavailable without the driver error, which
can carry hostnames and credentials. Validation errors never echo input.

*Tests:* `TestPanicIsRecoveredWithoutLeakingDetail`,
`TestReadinessDoesNotLeakDependencyErrorDetail`,
`TestValidationErrorsDoNotEchoInput`, `TestValidationErrorsDoNotLeakCredentials`.

---

## Boundaries 3–4 — API → queue → worker

### T-14 Job payload as an execution vector · **Mitigated**

A payload carrying a command line would make the worker a remote-execution
service for anything that can write to Redis.

Payloads are plain data and are re-validated on arrival rather than trusted
because we wrote them.

*Tests:* `TestJobPayloadCarriesNoExecutableFields`,
`TestInvalidTargetIsRejectedOnArrival`.

### T-15 Malformed or oversized queue payload · **Mitigated**

Payloads are size-capped and validated on read; a malformed payload is rejected
without crashing the worker, and a poison job is retired after `MaxAttempts`
rather than cycling forever.

*Tests:* `TestRedisQueueRejectsMalformedPayload`,
`TestJobExceedingMaxAttemptsIsRetired`, `TestPanicInJobDoesNotKillWorker`.

### T-16 Result rewriting by a replayed worker · **Mitigated**

A duplicate delivery upgrading a `PARTIAL` scan to `COMPLETED` would erase
evidence of degraded coverage.

State transitions are enforced in the domain model *and* in SQL — `Finalize`
only matches non-terminal scans.

*Test:* `TestFinalizeIsIdempotentAgainstReplay`, against a real database.

---

## Boundary 6 — Services → PostgreSQL

### T-17 SQL injection · **Mitigated**

Parameterised statements only. pgx's extended protocol refuses concatenated
multi-statement text, which enforces the rule structurally.

### T-18 Over-privileged database access · **Partial**

Least privilege is stated policy; today all components share one role. Separate
roles are Phase 11.

---

## Supply chain and CI

### T-19 Dependency compromise · **Partial**

grype and trivy run on every CI run; an SBOM is generated and retained.
`.grype.yaml` suppresses six CVEs in golang-migrate's Docker-based test drivers,
which `go version -m` confirms are not linked into any binary. Rules are scoped
to specific vulnerability IDs, so a new CVE in those modules still fails.

**Why partial:** no dependency pinning by digest, and no verification of scanner
binary provenance (see T-10).

### T-20 Compromised CI token · **Partial**

`contents: read` by default with no per-job escalation; third-party actions
pinned to immutable commit SHAs; `persist-credentials: false` on checkout.

**Why partial:** no branch protection or required reviews configured, so a
compromised account can still push directly to `main` — as happened, benignly,
with Phase 1.

### T-21 Malicious uploaded SBOM · **Open**

No SBOM upload endpoint exists yet. When one is added it must be treated as
hostile input: size-capped, schema-validated, and parsed defensively.

### T-22 Insecure webhook · **Open**

No webhook endpoint yet. When added it requires signature verification, replay
protection, and size caps.

---

## Summary

| Status | Count | Notable |
|---|---|---|
| Mitigated | 12 | T-01, T-02, T-03, T-05, T-06, T-07, T-12, T-13, T-14, T-15, T-16, T-17 |
| Partial | 7 | T-04, T-08, T-09, T-18, T-19, T-20 |
| Open | 4 | **T-11 (no auth)**, T-10, T-21, T-22 |

T-11 is the one to fix first, and it becomes urgent the moment a write endpoint
ships.

## Review triggers

Update when a trust boundary changes, a component is added, a threat changes
status, or a phase completes (§15.14, §21).
