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
is size-capped, and a result carrying any degradation reason is recorded as
*not* succeeded so it can never be normalized as if whole (ADR 010).

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

## Boundary 5 — Worker → Untrusted target content

### T-25 Malicious repository content at fetch time · **Partial**

Phase 3b added the fetch step, which is where SecureOps pulls
attacker-controlled content onto a machine it owns. `git` is a large program
with a long history of remote-triggered surprises, so the clone refuses every
capability it does not need (ADR 008):

- `protocol.allow=never` with only https and ssh re-enabled. This blocks `ext::`,
  which executes an arbitrary command named in the URL, and `file://`, which
  reads the worker's own disk. It also blocks a **bare local path**, because git
  treats one as the `file` transport — verified, not assumed.
- `--recurse-submodules=no`. A submodule is an attacker-controlled URL fetched
  on our behalf, bypassing the target validator entirely.
- `credential.helper=` empty, `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/true`.
  Git never attaches host credentials to an attacker-chosen URL, and a private
  repository fails fast instead of pinning a worker slot on a password prompt.
- `core.hooksPath=/dev/null` and `core.symlinks=false`.
- An allow-list environment, so the subprocess cannot inherit the database URL,
  the Redis password, or cloud credentials.
- Hard timeout, plus post-clone size and file-count limits. Exceeding one is a
  structured failure with its own scan `failure_reason`.

Partial rather than mitigated: the limits are enforced *after* the clone,
because git offers no reliable pre-flight size check. A hostile repository can
therefore cause a worker to write up to the limit before being stopped. The
workspace is ephemeral and destroyed either way, so the limit is what bounds the
damage.

*Tests:* `TestCloneArgsCarryTheSecurityControls`,
`TestCloneArgsTerminateOptionParsing`, `TestCloneEnvIsAnAllowList`,
`TestLocalPathsCannotBeCloned`, `TestMeasureEnforcesTheSizeLimit`,
`TestMeasureEnforcesTheFileCountLimit`, `TestMeasureDoesNotFollowSymlinks`.

### T-26 Harvested credentials in the results database · **Mitigated**

A secret scanner's output contains the credentials it found. Persisting that
verbatim, as §8 requires for raw results, would make the SecureOps database a
store of live credentials drawn from every repository ever scanned — and would
turn a SecureOps compromise into a compromise of every customer's third-party
systems.

Resolved in ADR 007 in favour of §15.3: gitleaks runs with `--redact`, so the
value never enters SecureOps' memory, and the adapter **verifies** redaction
before returning anything. Output that cannot be proven redacted is discarded
and the scanner result fails. Location, rule, line, entropy, and fingerprint all
survive, which is what an engineer needs in order to rotate the secret.

Verified against a public repository of planted secrets: 22 findings detected,
zero credentials persisted.

*Tests:* `TestAssertRedactedRejectsALiveSecret`, `TestUnredactedMatchIsStillRejected`,
`TestRedactionErrorDoesNotLeakTheSecret`, `TestScanFindsSecretsAndRedactsThem`,
`TestIsRedactedSecret`, `TestIsRedactedMatch`.

*Verified by control test:* removing `--redact` from the argv, and separately
neutering `assertRedacted`, each make the corresponding test fail.

### T-27 Scanner report written into the scanned tree · **Mitigated**

gitleaks scans every file under its source, so a report written inside the
checkout is scanned on the next run and its own contents reported as findings —
inflating counts silently. The report is written to a sibling directory inside
the ephemeral workspace instead.

*Tests:* `TestTheReportIsNotWrittenIntoTheScannedDirectory`, `TestScanIsRepeatable`.

### T-28 Scanner binary supply chain · **Partial**

Scanner binaries are built from source at a **pinned commit SHA**, with the
checkout verified by `git rev-parse` before building (ADR 009). A commit SHA is
content-addressed, so unlike a tag it cannot be moved — this is stronger than
verifying a publisher checksum, which comes from the same origin as the binary
it attests to.

This also closed a vulnerability problem rather than only a provenance one. The
published gitleaks 8.30.1 binary carries **32 HIGH/CRITICAL CVEs** — 21 in a Go
standard library from the 1.24.11 toolchain it was built with, 11 in x/crypto
and x/text — and 8.30.1 is the latest release, so there was nothing to upgrade
to. Rebuilding with this project's toolchain and patched x/ libraries brings the
image to **0 HIGH/CRITICAL**, with output verified byte-identical to the release
binary across 22 findings.

Partial, not mitigated, for two reasons:

- The build trusts GitHub to serve the content at that SHA. A compromise of the
  repository's history would still be inherited. Signature or provenance
  verification (Sigstore) would close this and is the remaining work.
- Pinned dependency bumps go stale as new advisories land. `make scan-image` is
  what surfaces that, and it is a manual step — see T-29.

Related to T-10.

### T-29 Container images are not scanned by the pipeline · **Mitigated**

`make security` and the CI self-scan ran `trivy fs`, which scans the filesystem
and Dockerfiles but never a **built image**. That is how a worker image carrying
32 HIGH/CRITICAL CVEs reached a working state unnoticed — it was found only by
running `trivy image` by hand.

The CI self-scan job now builds both images and scans them, failing on any
HIGH/CRITICAL. `make scan-image` runs the same commands locally. It is
deliberately not part of `make security`, which must stay fast enough to run
before every commit — CI is where the slower, thorough check belongs.

This closed on the same PR that added a second scanner binary to the worker
image, which is exactly when the gap would have mattered again: syft's
source build shipped two x/mod advisories that the check caught.

### T-30 Worker filesystem layout leaked into stored artifacts · **Mitigated**

Syft's file cataloger names components by **absolute path**, so an SBOM
generated from an ephemeral, randomly-suffixed workspace embedded the worker's
internal layout — and produced a different document for every scan of the
identical commit. That is a minor information disclosure and a real
reproducibility defect: Phase 4 cannot fingerprint a component's identity across
scans if the document changes each run.

The file cataloger is disabled, which costs nothing (it contributed 13 file
components and zero library components on this repository), and the adapter
asserts the result: an SBOM referencing the workspace or its parent is discarded
and the scanner result fails.

*Tests:* `TestWorkspacePathLeakIsRejected`, `TestWorkspaceParentPathIsAlsoRejected`,
`TestRealSBOMContainsNoWorkspacePaths`, `TestArgsDisableTheFileCataloger`,
`TestSBOMComponentsAreStableAcrossRuns`.

*Verified by control test:* dropping `--select-catalogers -file`, and separately
neutering the assertion, each make the corresponding test fail.

### T-31 A scanner succeeds against untrustworthy data · **Partial**

A scanner can exit 0, emit well-formed output, and still be wrong in the one
direction that matters: reporting fewer findings than exist.

Grype matches against a local vulnerability database. It does ship a staleness
guard — `db.validate-age`, five days by default — but that guard **fails the
scan**, discarding findings that are real, so SecureOps disables it (ADR 010).
With it off, a stale database produces a **false clean**: exit 0, well-formed
output, fewer vulnerabilities than exist, and no signal anywhere for a gate to
read. Verified by forcing the age limit to one second: grype exits 1 with the
guard on, and returns a full report from the same database with it off.

Trivy has the same property; ZAP will have its own variants (an unauthenticated
crawl, a ruleset that failed to load).

This is more dangerous than a scanner that crashes. A crash is visible and
someone fixes it; a false clean is indistinguishable from good news.

`ScannerResult` carries a set of **degradation reasons** rather than a single
flag or a bare `degraded` status. Any reason at all makes `Succeeded()` false,
so the scan settles at `PARTIAL` and `complete_coverage` is false — and the
reason itself reaches the API, because §12 requires a gate to explain the exact
conditions behind its verdict, and "degraded" alone is not actionable.

**Why partial:** the mechanism is in place and enforced, but the only reason
anything currently emits is `output_truncated`. `stale_vulnerability_db` lands
with the Grype adapter, and until then no scanner can produce the
succeeded-but-degraded state this exists for. The mechanism is deliberately
ahead of its first producer; that is a gap in coverage, not in design.

*Tests:* `TestUnknownDegradationReasonStillDegradesScan`,
`TestDegradedIsDistinctFromFailed`, `TestTruncatedResultDegradesScan`,
`TestScannerDegradationsReachTheClient`.

*Verified by control test:* making `Succeeded()` ignore degradations, dropping
the reasons in the worker, and rendering them as `null` in the API each make the
corresponding test fail.

---

## Summary

| Status | Count | Notable |
|---|---|---|
| Mitigated | 17 | T-01, T-02, T-03, T-05, T-06, T-07, T-11*, T-12, T-13, T-14, T-15, T-16, T-17, T-26, T-27, T-29, T-30 |
| Partial | 10 | T-04, T-08, T-09, T-18, T-19, T-20, T-24, T-25, T-28, T-31 |
| Open | 4 | **T-23 (no authorization)**, T-10, T-21, T-22 |

\* T-11 is mitigated by an interim control (ADR 006) that Phase 11 replaces.

**T-23 is now the one to fix first.** Authentication landed in Phase 3 alongside
the first write endpoints; authorization did not, and a single-tenant assumption
is the only thing making that acceptable. It becomes urgent the moment a second
tenant, or a second class of user, exists.

Phase 3a widened the attack surface: `POST /scans` is the first endpoint that
accepts an attacker-chosen target. The SSRF guard (T-04) and the
argument-injection defences (T-05) moved from theoretical to load-bearing, and
both are now exercised at the API boundary as well as in the worker.

Phase 3b widened it much further. The worker now **fetches and executes against
attacker-controlled content** (T-25), which is the single most dangerous thing
this system does, and it handles credentials it discovers (T-26). Both are new
with this phase and both are the reason the worker runs as a separate,
non-root, read-only container with an ephemeral tmpfs workspace and no package
manager.

## Review triggers

Update when a trust boundary changes, a component is added, a threat changes
status, or a phase completes (§15.14, §21).
