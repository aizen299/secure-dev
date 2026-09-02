# Threat Model

Threats are enumerated per trust boundary (see `trust-boundaries.md`). Each
carries an honest status:

- **Mitigated** — a control exists and a test covers it
- **Partial** — a control exists but does not cover the whole threat
- **Open** — no control yet

"Mitigated" is never claimed on the strength of an intention. Where a test
enforces the control, it is named, because a security control without a test is
a comment.

Last reviewed: 2026-09-02, after Phase 6's threat-intelligence capture.
Covers Phases 1-5 in full, and Phase 6 up to EPSS; the risk engine is not
yet built.

---

## Boundary 5a — Worker → untrusted target: execution

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

**Why partial:** every adapter now validates its own output before persisting
it, and normalization (Phase 4) has not started, so nothing yet parses that
output into the canonical model where a hostile value would do damage.

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

**The impact grew substantially in Phases 4-6 while the vulnerability stayed the
same.** When this was written the API served project names and scan statuses.
It now serves every project's full vulnerability inventory, the file paths of
correlated issues, and EPSS exploitation probabilities — which is to say, a
ranked attack plan. See T-36 and T-38. Nothing about the missing control
changed; what it fails to protect did.

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

## Boundary 5b — Worker → untrusted target: content and results

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

### T-31 A scanner succeeds against untrustworthy data · **Mitigated**

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

The Grype adapter is the first real producer. It disables grype's own age
guard deliberately — that guard exits 1 and discards findings that are real —
assesses the same five-day threshold itself, and degrades instead, keeping both
the findings and the warning (ADR 012). A report that cannot prove its own
freshness degrades as `unknown_vulnerability_db`, because silence is not
evidence of freshness. A database grype marks invalid is refused outright: stale
data is correct but incomplete, invalid data is wrong in ways that cannot be
characterised.

*Tests:* `TestUnknownDegradationReasonStillDegradesScan`,
`TestDegradedIsDistinctFromFailed`, `TestTruncatedResultDegradesScan`,
`TestScannerDegradationsReachTheClient`, `TestStaleDatabaseDegrades`,
`TestStalenessBoundary`, `TestUnprovableFreshnessDegrades`,
`TestInvalidDatabaseIsRefusedNotDegraded`.

*Verified by control test:* making `Succeeded()` ignore degradations, dropping
the reasons in the worker, and rendering them as `null` in the API each make the
corresponding test fail.

### T-32 The vulnerability database as supply chain · **Partial**

Grype downloads a 2.0 GB database over the network and then trusts it to decide
what counts as vulnerable. Anything that can alter it can make a vulnerable
dependency look clean, without touching a single line of SecureOps or of the
scanned repository. That is supply chain in exactly the sense §15.7 means, and
it is a more attractive target than the scanner binary: it changes daily, so a
substitution is easier to hide in normal churn.

`GRYPE_DB_VALIDATE_BY_HASH_ON_START=true` — the database is verified against the
hash published alongside it on every run, so a modified archive is rejected.
Provisioning happens once at worker startup, before any job is claimed, so the
download never coincides with attacker-controlled content on disk (ADR 012).

**Why partial:** the hash is published by the same origin that serves the
database, so this detects corruption and interception but not a compromise of
Anchore's publishing infrastructure — the same limitation ADR 009 records for
publisher checksums generally. Pinning a known-good database digest would close
it and would also freeze vulnerability data, which is worse. No transparency log
exists for this artifact to check against.

*Test:* `TestEnvDisablesEgressAndGrypesOwnAgeGuard` asserts hash validation stays
on; a control test confirms the assertion fails when it is removed.

### T-33 Unfixable advisories in a vendored scanner dependency · **Partial**

Grype vendors `github.com/docker/docker` for image scanning. Five advisories
against it report `Fixed in: N/A`, and v28.5.2 is the newest release that
exists, so no grype version avoids them. Two are HIGH under trivy, which is the
gate `make scan-image` and CI enforce.

Everything fixable was fixed first: grype pinned up to v0.118.0,
`golang.org/x/mod` to v0.40.0, `go.opentelemetry.io/otel` to v1.44.0.

The remaining two are recorded as **accepted risk** in `.trivyignore.yaml`,
scoped to those two CVE IDs, scoped to the grype binary's path, and carrying an
expiry date trivy enforces. Approved by the project owner per §24. The reasoning:
both are Docker Engine API handlers, the worker runs no daemon and mounts no
socket, and the adapter declares filesystem targets only, so grype's
image-scanning path — the only reason the dependency is linked — is never
invoked.

**Why partial, and stated plainly:** this is a judgement that the exposure needs
a Docker daemon we do not run. It is not proof the code is unreachable.
govulncheck reports the vulnerable symbols as present in the binary; an early
assumption that they would not even be compiled in was wrong. The exception
expires rather than persisting, which is the control that keeps this from
quietly becoming permanent.

A second gap this exposed is now closed: govulncheck runs as a second
binary-level gate (ADR 013). It found **eleven** advisories across the three
scanner binaries where trivy found two, and **four of them had published
fixes** — archive-parsing flaws in the exact code path a secret scanner points
at untrusted repositories. Those were fixed, not accepted.

The open question this entry recorded is also answered, and it does not change
the verdict. Measured with a call behind a runtime-false condition: govulncheck's
binary mode reports symbols surviving linker dead-code elimination and performs
no call-graph analysis, while source mode proves only static reachability. Both
reported the unreachable call. So neither mode establishes runtime
exploitability, and "present in the binary" remains the accurate description of
what is known here.

*Also accepted, in `.govulnignore.yaml`:* `GO-2026-5932`
(`x/crypto/openpgp`, unmaintained, no fixed version) across all three scanner
binaries, plus the same five Docker advisories under their Go ids. Same rules —
per-binary, justified, expiring — with one addition: an entry that stops
matching anything fails the build, so the list cannot rot.

*Verified by control test:* backdating `expired_at` makes the build fail again,
renaming the CVE ids makes the real two resurface, and pointing `paths` at
another binary removes the suppression — so the exception is narrow in all three
dimensions rather than a disabled scanner.

*Revisit:* before image targets ship (Trivy adapter), which invalidates the
reasoning above.

### T-34 Matched source stored as a finding · **Mitigated**

Semgrep can embed the matched line in every finding (`extra.lines`). For a rule
that fires on a credential, that line **is** the credential, and §15.3 forbids
storing it. ADR 007 raised this when Gitleaks landed and left it open, because
nothing then produced such output.

Unauthenticated semgrep writes `requires login` there instead — verified against
a local ruleset with a planted key, which appeared nowhere in the output. That
is a property of semgrep's login state, not of any flag SecureOps sets, so it is
not relied on.

The adapter checks every finding before persisting and discards the entire
result if any carries source, whether or not the source looks like a secret: a
control that tried to tell the difference would eventually guess wrong. The
environment allow-list is the first line of the same defence — `SEMGREP_APP_TOKEN`
cannot be inherited, because nothing unlisted reaches a scanner subprocess.

`p/secrets` is deliberately absent from the default rulesets. Gitleaks owns
secret detection (§6), and including it would mean reimplementing ADR 007's
redaction control here a second time.

*Tests:* `TestMatchedSourceIsRefused` (a credential and ordinary source, both
refused), `TestRedactedSourceIsAccepted`, `TestIsRedactedSource`,
`TestEnvIsAnAllowListWithoutTokens`, and `TestScanAgainstRealSemgrep`, which
holds a live run to the same assertion.

*Verified by control test:* neutering the assertion makes the leak fixtures pass.

### T-35 Source content stored as a misconfiguration finding · **Mitigated**

Trivy reports each misconfiguration with the source lines that caused it, in
`CauseMetadata.Code.Lines[]`. Infrastructure-as-code is where hardcoded secrets
live, so those lines are routinely a credential: a Terraform resource with a
password produces a finding whose cause lines contain that password. Measured
rather than assumed — a planted value appeared verbatim in the JSON.

It appeared in **two** fields. `Content` is the line; `Highlighted` is the same
line with ANSI colour. Redacting only the obvious one leaves the secret in the
document, which is the sort of thing that is found by looking at output rather
than by reading a schema.

Trivy offers no flag to omit them (`--render-cause` affects only the table
report), so the adapter rewrites the document before anything is persisted:
structural walk, three fields replaced with a fixed marker, file and line
numbers and rule and severity all kept. A fixed marker rather than truncation,
because the first characters of a line containing a credential can still be the
credential.

The rewrite walks a decoded structure, so a trivy schema change could move those
fields somewhere it does not look. `assertNoSourceContent` re-walks the result
and discards the whole report if anything survived, so a schema change makes
scans fail rather than leak.

This makes trivy the only adapter whose stored output is not byte-identical to
what the scanner emitted, recorded in ADR 015 rather than left as a surprise.

*Tests:* `TestRedactionRemovesSourceContent`, `TestRedactionKeepsWhatRemediationNeeds`,
`TestAssertionCatchesWhatTheRewriteMisses`, `TestHighlightedIsRedactedToo`, and
`TestScanAgainstRealTrivy`, which holds a live run to the same assertion.

*Verified by control test:* dropping `Highlighted` from the redacted field list,
disabling the rewrite, and neutering the assertion each make the corresponding
test fail.

---

## Boundary 7 — Stored findings and derived views

New with Phases 4-6. Until Phase 4, a scan produced raw output and a status;
nothing durable described what was wrong with a project. Now SecureOps keeps a
queryable record of every vulnerability it has ever seen, correlates those
records into issues, attaches exploitation likelihood to them, reduces the whole
picture to a single number that a CI gate will eventually act on, and turns that
number into advice somebody will act on directly.

That record is a security asset in its own right, and the threats below are
about the asset rather than about the scanning that produced it.

### T-36 The findings store as an attack map · **Partial**

Concentrating every finding for every project into one queryable place creates
something no individual scan report was: a maintained, deduplicated, severity-
ranked inventory of how to attack the software this instance watches.

Phase 6 sharpened it. EPSS attaches a calibrated exploitation probability to
each finding, so `GET /api/v1/projects/{id}/findings` sorted by that field is
not a vulnerability list — it is a prioritised exploitation roadmap, ordered by
what is most likely to work right now.

**The control is authentication and nothing else.** T-11 gates every endpoint
under `/api/v1`, and that is real. But T-23 means every valid token is
equivalent, so any credential reads every project's inventory. There is no
tenancy boundary to breach.

This does not change T-23's likelihood. It multiplies its impact, and it is the
reason T-23 remains the first thing to fix: the same missing control now
discloses far more than it did when the API served project names and scan
statuses.

Partial rather than Open because authentication genuinely bounds it, and because
the most dangerous single field — a detected secret's value — is never stored at
all (T-26, T-34, T-35).

*Fix:* Phase 11 (RBAC, project scoping at the data layer).

### T-37 A scan falsely resolving a finding · **Mitigated**

A finding wrongly marked `resolved` tells someone a vulnerability was fixed when
nobody checked. It is the same class of error as reporting a `PARTIAL` scan as
clean (§13), reached through the lifecycle instead of through the status field,
and it is worse than a missed finding because it actively ends an
investigation.

Two ways in, both closed. A scanner that did not run cannot resolve its
findings: only scanners that completed without degradation are eligible. And
resolution requires **every** scanner that has ever reported a finding to have
completed — checking only the first reporter would resolve a grype+trivy finding
the moment grype came back clean, even with trivy failed and never asked.

The conservative direction is deliberate: dropping a scanner from a project
leaves its old findings open rather than silently declaring them fixed.
Stale-but-open is a state someone can see; a false `resolved` is not.

*Tests:* `TestAFailedScannerResolvesNothing`,
`TestOneFailedReporterBlocksASharedFinding`.

*Verified by control test:* removing the all-reporters clause makes the second
test fail while the other four lifecycle tests still pass — which is why the
defect existed unnoticed in the first place.

### T-38 Derived views disclosing repository structure · **Partial**

Findings deliberately carry no file path: location lives on the occurrence, and
`GET /findings` does not serve it.

Correlated issues do. A file-keyed issue's identity **is** a path in the scanned
repository, published as `key_value` on `GET /issues`. For a private repository
that is structure disclosure — directory layout, and which files carry both a
secret and a code weakness.

Bounded rather than closed: the path is the only thing exposed, never file
content, and the same authentication gate applies. It is recorded because the
disclosure is a consequence of the correlation design rather than an oversight,
and because whoever implements Phase 11 should scope issues exactly as they
scope findings.

*Fix:* Phase 11, alongside T-36.

### T-39 Poisoned threat intelligence · **Mitigated**

Scanner output is untrusted (§15.7), and threat intelligence arrives inside it.
A hostile or broken EPSS value could distort prioritisation — the more so once
the risk engine consumes it.

Values are range-checked at the adapter, and a bad one drops the *value* while
keeping the finding: discarding a real vulnerability because its likelihood
metadata was malformed would be the wrong trade. Every drop is recorded as a
parse note rather than swallowed.

Provenance is mandatory. An EPSS with no source or no observation date is
rejected, because a number of unknown origin and unknown age looks like evidence
without being any. The rule is enforced three times independently — a pointer in
Go, an omitted JSON field, and a database CHECK — so a partially written value
cannot exist at rest.

Absence is never zero. EPSS probabilities are genuinely small, so a zero default
would be indistinguishable from a real signal saying "essentially nobody is
exploiting this" (ADR 018).

*Tests:* `TestABadEPSSDropsTheValueNotTheFinding`, `TestProvenanceIsRequired`,
`TestOutOfRangeValuesAreRejected`, `TestAbsentEPSSDoesNotBecomeZero`,
`TestAPartialEPSSRowIsRejectedByTheDatabase`.

*Verified by control test:* forcing the store to write `0.0` for an absent value
is rejected by the database constraint before the assertion runs.

### T-40 Correlation cost as a denial of service · **Mitigated**

Correlation compares findings pairwise within a bucket. A hostile repository
engineered to produce many thousands of findings sharing one CVE, component, or
file would make that quadratic, inside the scan-completion path.

Buckets are capped at 500. Beyond that the bucket is truncated in fingerprint
order — deterministically, so the same findings survive every run — and the
truncation is *reported* rather than absorbed, following ADR 010: silence would
be indistinguishable from "nothing correlated".

*Tests:* `TestAnOversizedBucketIsTruncatedAndReported`,
`TestTruncationIsDeterministic`.

### T-41 Correlation asserting a relationship that does not exist · **Mitigated**

Not a classic attack, but a security defect: a wrong correlation sends someone
to investigate a link nobody has evidence for, and an escalated severity built
on it misdirects remediation effort.

Issues are keyed by a single shared attribute, never by transitive closure over
the link graph — A related to B by CVE and B to C by file must not place A and C
in one issue, because no rule ever evaluated that pair. Severity escalates by at
most one step, only across distinct domains, and never mutates the members it
was derived from. Every link and every membership carries readable evidence.

Dismissed findings are excluded entirely: correlating a `false_positive` back
into a live issue would resurrect a decision somebody already made.

*Tests:* `TestIssuesDoNotChainTransitively`, `TestEscalationDoesNotMutateMembers`,
`TestDismissedFindingsAreNotCorrelated`.

### T-42 A risk score read as more complete than it is · **Mitigated**

The risk engine scores the findings it has. A scan in which a scanner failed
produces fewer findings, and fewer findings produce a *lower* score — so
degraded coverage is arithmetically indistinguishable from an improvement. A CI
gate reading only the number would pass a release precisely because the scanner
that would have blocked it crashed.

Every stored score carries the status of the scan it was computed for, joined
at read time rather than copied so it cannot go stale, and the API exposes both
`scan_status` and a pre-applied `complete` flag. §13's rule that `partial` is
never a synonym for `completed` therefore reaches the consumer of the score,
not just the scan record.

This is a control the Phase 8 policy engine must actually use; the mitigation
here is that the information is present and unavoidable, not that a gate exists
yet to honour it.

*Tests:* `TestRiskReportsWhetherTheScanWasComplete`,
`TestRiskScoreSurvivesTheRoundTrip`.

### T-43 A re-tuning silently changing what stored scores mean · **Mitigated**

Risk weights are configuration by design (§10), which means they will be
re-tuned. A score of 62 computed under one weight table and a score of 71
computed under another are measurements of different things, and a trend line
drawn across the change is fiction that looks like evidence — the more
dangerous kind, because it invites a decision.

Every persisted score records a digest of the weight configuration in force.
Scores with different digests are visibly incomparable, and the digest is
canonical by construction so identical weights always produce it identically.

*Tests:* `TestRiskScoreSurvivesTheRoundTrip`, `TestAScanPersistsItsRiskScore`,
`TestDefaultWeightsMatchTheDesignDocument`.

### T-44 Remediation advice that sends effort the wrong way · **Mitigated**

Not a classic attack, but a security defect with the same shape as T-41. A
remediation plan is acted on: a wrong upgrade target wastes the one window
somebody had to fix something, and a fabricated fix is worse than no advice
because it looks like an answer.

No action names a version no scanner reported (§11, §25.6). Where several
advisories on one component report different fixed versions, the action lists
them all rather than choosing — choosing needs ecosystem-specific version
ordering, and a comparator correct for semver is wrong for PEP 440 or Debian
epochs. Fix state is four-valued, so "no fix yet", "there will never be one",
and "nobody told us" cannot collapse into a claim that an upgrade exists; the
database enforces the same rule independently of the Go model.

*Tests:* `TestNoActionNamesAVersionNoScannerReported`,
`TestUnknownFixStateProducesNoUpgrade`, `TestWontFixNeverCarriesAnUpgradeTarget`,
`TestTheDatabaseRejectsAVersionOnAnUnfixableState`.

### T-45 Generated content presented as verified remediation · **Mitigated**

§11 permits AI for contextual explanation and prioritization guidance and
forbids it for the facts of a fix; §25.6 forbids presenting AI-generated
remediation as verified, and forbids labelling deterministic rules "AI". The
failure mode is a plausible-sounding fix with no provenance being read as
vendor guidance and applied.

Every statement in an action carries its source — `vendor`, `scanner`, or
`derived` — in the model and in the API response. `ai_explanation` is declared
so that AI content would be structurally visible if it were ever added, and is
never produced: no model integration exists, and §25.15 forbids treating Claude
Code or MCP as a runtime dependency. Prioritization is arithmetic, not
judgement, so no part of the ranking is generated either.

*Tests:* `TestNoStatementIsEverSourcedAI`, `TestNoRemediationStatementIsSourcedAI`.

---

## Summary

| Status | Count | Notable |
|---|---|---|
| Mitigated | 28 | T-01, T-02, T-03, T-05, T-06, T-07, T-11*, T-12, T-13, T-14, T-15, T-16, T-17, T-26, T-27, T-29, T-30, T-31, T-34, T-35, T-37, T-39, T-40, T-41, T-42, T-43, T-44, T-45 |
| Partial | 13 | T-04, T-08, T-09, T-18, T-19, T-20, T-24, T-25, T-28, T-32, T-33, T-36, T-38 |
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

Phase 3b widened it much further. The worker now **fetches and parses
attacker-controlled content** (T-25), which is the single most dangerous thing
this system does, and it handles credentials it discovers (T-26). Both are new
with this phase and both are the reason the worker runs as a separate,
non-root, read-only container with an ephemeral tmpfs workspace and no package
manager.

Parses rather than executes, stated precisely because the distinction bounds the
threat: all five scanners are static analysers, and the fetch disables hooks,
symlinks, submodules, and every protocol but https and ssh. The exposure is
parser bugs in five parsers, not arbitrary code execution by design. That is
still the highest-value boundary; it is not the same threat as running the
target's build.

**Phases 4-6 added a boundary rather than widening one.** SecureOps now keeps a
durable, correlated, likelihood-ranked record of every vulnerability it has
seen. Nothing about scanning changed; what changed is that the product now holds
an asset worth stealing (T-36), publishes derived views that disclose more than
the findings themselves (T-38), and can be wrong in a new and dangerous way — by
declaring a vulnerability fixed when nobody checked (T-37).

The controls added with them are mostly about *not lying*: a scan may not
resolve what it did not verify, correlation may not assert links it cannot
explain, and a threat-intelligence value may not exist without provenance. Those
are security properties, not quality ones — each failure mode ends an
investigation that should have continued.

## Review triggers

Update when a trust boundary changes, a component is added, a threat changes
status, or a phase completes (§15.14, §21).

This document went four pull requests without an update — Phases 4, 5, and 6's
threat-intelligence capture all landed while it still described Phase 2. No
CI check enforces the trigger above, so it depends on the reviewer noticing.
Worth remembering that "documentation updated where necessary" is part of the
Definition of Done (§23), and that a threat model describing a system two phases
old understates its own open threats — which is exactly what happened to T-23.
