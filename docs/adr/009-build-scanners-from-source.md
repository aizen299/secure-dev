# ADR 009: Build scanner binaries from pinned source, not release archives

- **Status:** Accepted
- **Date:** 2026-08-31

## Context

The worker image needs the scanner binaries. The obvious approach — download the
publisher's release archive, verify its SHA-256 against the published checksums
file, install it — was what the first version of `worker.Dockerfile` did.

Scanning the resulting image told a different story:

```console
$ trivy image --severity HIGH,CRITICAL secureops-worker:latest
usr/local/bin/gitleaks (gobinary)   Total: 32 (HIGH: 31, CRITICAL: 1)
  stdlib               21   installed v1.24.11
  golang.org/x/crypto  10   installed v0.35.0
  golang.org/x/text     1   installed v0.22.0
```

Thirty-two HIGH/CRITICAL vulnerabilities, none of them in gitleaks' own code.
Twenty-one are in the Go standard library, because the release was built with Go
1.24.11. The rest are in two `golang.org/x` libraries pinned in its `go.mod`.

There is no newer release to upgrade to: 8.30.1 is the latest. Waiting for
upstream to rebuild is not a plan, and this is not a gitleaks-specific problem —
any Go-based scanner ships whatever toolchain and dependency versions its
maintainers happened to release with, and four of the six planned adapters are
Go programs.

Shipping a security product whose own scanner container carries 32 known
HIGH/CRITICAL vulnerabilities is not defensible, particularly when that
container is the one component that executes against attacker-controlled input.

Two smaller findings sharpened the decision:

- **Nothing in the pipeline would have caught this.** `make security` and CI run
  `trivy fs`, which scans the filesystem, not built images. The 32 CVEs were
  found by running `trivy image` by hand.
- **The checksum was weaker than it looked.** It is published by the same
  origin as the binary, so it detects tampering in transit but not a compromise
  of the release process itself.

## Decision

**Build scanner binaries from source at a pinned commit SHA, using this
project's Go toolchain, with security-patched dependencies.**

For gitleaks:

| | |
|---|---|
| Source | `git clone` pinned to commit `83d9cd68…` (v8.30.1), verified with `git rev-parse` after checkout |
| Toolchain | `golang:1.27-alpine`, the same version the rest of the project builds with |
| Dependencies | `golang.org/x/crypto@v0.55.0`, `golang.org/x/text@v0.41.0`, pinned explicitly |
| Version | `-X …/version.Version=8.30.1`, asserted at build time |

Result: **0 HIGH/CRITICAL**, down from 32.

### Why a commit SHA rather than a tag

A tag is a mutable pointer; the maintainer, or anyone who compromises the
account, can move it. A commit SHA is content-addressed and cannot be moved
without detection. This is strictly stronger than the publisher-checksum
approach it replaces, which is the point: the change improves provenance rather
than trading it away for patched dependencies.

### Why bumping dependencies is safe here

Changing a dependency version upstream did not test is a real risk, so it was
verified behaviourally rather than assumed. Both the released binary and the
source-built one were run against a public repository of 22 planted secrets:

```text
release binary : 22 findings
source-built   : 22 findings
identical      : True
unredacted     : 0
```

Byte-identical rule IDs, files, lines, and redaction state. The bumps are
confined to two `golang.org/x` libraries, which hold Go's compatibility promise.

### The version string is a correctness requirement, not cosmetics

Building without the `-ldflags` version injection produces a binary that reports
`version is set by build process`. §7 rule 6 requires the scanner version to be
captured per scan and persisted, so that string would be stored as the scanner
version for every finding, and results would not be reproducible against a known
tool version. The build therefore **asserts** the version output and fails if it
is wrong. This was caught during implementation, having silently shipped in a
first attempt.

## Alternatives considered

**Keep the release binary and suppress the CVEs.** Rejected. Thirty-two
suppressions is not a scoped exception, it is a policy of ignoring the scanner's
findings — in the container that runs against untrusted input, in a product
whose entire purpose is not doing that. ADR 005 accepted six ID-scoped ignores
for modules provably not linked into any binary; these are linked, and they are
in the process that touches hostile content.

**Keep the release binary and document the risk.** Rejected for the same reason,
with the added problem that "documented" would quietly become "permanent".

**Rebuild with the current toolchain but leave dependencies untouched.**
Genuinely tempting: it removes all 21 stdlib CVEs with no divergence from
upstream's tested dependency set, leaving 11. Rejected because the remaining 11
are in x/crypto, which gitleaks uses for key parsing — precisely the code path
that handles attacker-supplied content — and the behavioural check showed the
bump changes nothing observable.

**Use the upstream container image.** Rejected: it inherits the same binary,
adds a base image outside our control, and does not run as the UID our
compose/Kubernetes workspace ownership expects.

## Consequences

- The worker image builds in the region of a minute longer. Acceptable.
- **Every future adapter follows this pattern.** Semgrep is Python, so it will
  need its own treatment; Syft, Grype, and Trivy are Go and fit this one
  directly. Each addition must be checked with `make scan-image`, not assumed.

  Syft was the first to exercise this, and it justified the "not assumed" part:
  a plain rebuild left two `golang.org/x/mod` advisories that only the image
  scan surfaced, needing a pinned bump exactly as gitleaks had needed for
  x/crypto. Its output was verified identical to the release binary across 86
  components before the bump was accepted.
- **A pin is a standing commitment, not a one-time fix.** CVE-2026-56854
  (CRITICAL, `x/crypto`) was published against the v0.52.0 pin recorded above,
  and the image scan in CI caught it on its second run — the pinned version was
  clean when chosen and was not clean a day later. Bumping to v0.55.0 forced
  x/text to v0.41.0 with it, since x/crypto requires it; the two move together.
  Equivalence re-verified against the release binary on a synthetic corpus
  (identical rule, file, and line for every detection) before the bump was
  accepted. This is the recurring cost this ADR accepted, arriving on schedule.
- Upgrading a scanner is now: change the commit SHA and version, rebuild,
  confirm the version assertion passes, and re-run the corpus comparison. That
  is more work than bumping a version string, and it is the correct amount of
  work for a binary that executes against hostile input.
- Pinned dependency bumps will go stale as new advisories land. `make scan-image`
  is what surfaces that; it is deliberately not part of `make security`, which
  must stay fast enough to run before every commit.
- **`make scan-image` closes a real coverage gap** in the self-scan. It now also
  runs in the CI self-scan job, which builds both images and fails on any
  HIGH/CRITICAL, so the coverage is automatic rather than dependent on someone
  remembering (threat model T-29). It stays out of `make security`, which must
  remain fast enough to run before every commit.
