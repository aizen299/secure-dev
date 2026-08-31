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

### T-11 Unauthenticated access · **Mitigated (interim)**

Closed in Phase 3, in the same change that introduced the first write endpoints
(`POST /projects`, `POST /scans`). Every `/api/v1` endpoint except health
requires a bearer token (ADR 006).

What this stops: an anonymous caller enqueueing unbounded scan jobs, using the
target validator as an SSRF oracle to map which internal hosts resolve, or
reading every project's scan history.

The controls, all enforced at startup rather than per request, so a weak
configuration cannot be deployed:

- at least one token is required, in every environment — the API refuses to
  start without one, so there is no permissive fallback path;
- secrets must be at least 32 characters;
- secrets are hashed at load, compared as SHA-256 digests with
  `subtle.ConstantTimeCompare`, and every configured credential is checked on
  every request, so neither the outcome nor the matching credential's position
  is observable through timing;
- a rejected token is never logged, echoed, or included in the challenge.

Health endpoints stay open deliberately: a liveness probe that needs a
credential fails during a rotation, and an orchestrator would then restart a
healthy process.

*Tests:* `TestEveryResourceEndpointRequiresAuthentication` (enumerates the whole
authenticated surface, so a route added without the gate fails),
`TestBadCredentialsAreRejected`, `TestAuthenticateRejectsPrefixesAndExtensions`,
`TestNewRequiresAtLeastOneCredential`, `TestNewEnforcesMinimumTokenLength`,
`TestTheRejectedTokenIsNeverEchoed`,
`TestIntegrationEndpointsRejectMissingCredentials`.

*Verified by control test:* removing `r.Use(s.requireAuth)` from the router
makes `TestEveryResourceEndpointRequiresAuthentication` fail.

### T-23 No authorization model · **Open**

The other half of what T-11 used to cover, restated separately because
authentication is now done and authorization is not.

Every valid token is equivalent. There is no tenancy boundary, no per-project
scoping, and no role model, so any credential reaches any project. This is safe
only for a single-tenant deployment, which is what SecureOps is today.

A token labels a client, not a person, so "who ran this scan?" is answerable
only to the granularity of that label. There is also no revocation short of a
restart.

Phase 11 owns the fix: the four RBAC roles (Admin, Security Engineer, Developer,
Viewer), authorization checked at the API boundary *and* at the data layer for
project scoping.

### T-24 No durable audit log · **Partial**

§15.6 requires security-sensitive actions to be audit-logged with actor, time,
and before/after values. Today every mutating request emits a structured log
line carrying the authenticated principal's label, the method, the path, and the
response status. That is an audit trail, but not the one §15.6 describes: there
is no append-only store, no previous/new values, and no queryable history.

The gap is deliberate rather than overlooked. The `audit_logs` table belongs
with the entities it records changes to — findings, policies, remediation
actions — which arrive in Phases 4–8. Attributing actions now means Phase 11
starts with a populated call path rather than retrofitting identity onto
anonymous handlers.

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
| Mitigated | 13 | T-01, T-02, T-03, T-05, T-06, T-07, T-11*, T-12, T-13, T-14, T-15, T-16, T-17 |
| Partial | 7 | T-04, T-08, T-09, T-18, T-19, T-20, T-24 |
| Open | 4 | **T-23 (no authorization)**, T-10, T-21, T-22 |

\* T-11 is mitigated by an interim control (ADR 006) that Phase 11 replaces.

**T-23 is now the one to fix first.** Authentication landed in Phase 3 alongside
the first write endpoints; authorization did not, and a single-tenant assumption
is the only thing making that acceptable. It becomes urgent the moment a second
tenant, or a second class of user, exists.

Phase 3 also widened the attack surface: `POST /scans` is the first endpoint
that accepts an attacker-chosen target. The SSRF guard (T-04) and the
argument-injection defences (T-05) moved from theoretical to load-bearing, and
both are now exercised at the API boundary as well as in the worker.

## Review triggers

Update when a trust boundary changes, a component is added, a threat changes
status, or a phase completes (§15.14, §21).
