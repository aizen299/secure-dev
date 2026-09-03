# ADR 025: Container image targets, and what an image finding is

- **Status:** Accepted
- **Date:** 2026-09-03

## Context

`KindImage` has been fully modelled and validated in `internal/scanners/target.go`
since Phase 2, and `POST /scans` accepts it. No adapter serves it, so every image
scan is accepted and then fails with "no registered scanner supports this target
kind". CLAUDE.md §26 records this as a deferral rather than an oversight.

The cost of the deferral is not a missing feature. It is that §9's worked example
— a Grype CVE on a dependency, a Semgrep misuse of it, and Trivy finding the same
package in a production image, escalated to one CRITICAL issue — **cannot be
demonstrated**. That example is the product identity in §2: "SecureOps turns
fragmented security scanner output into one contextual security decision." A
platform that cannot cross the repository/image boundary is a platform that
correlates within one artifact, which is the thing §2 says SecureOps is not.

Three questions have to be answered before an adapter can be written, and each is
a §24 material change: what an image finding's identity is, what the canonical
model gains, and what egress a worker is permitted during a scan of
attacker-controlled content.

### What was measured first

Design here follows measurement rather than assumption. Against trivy 0.74.0:

- **Language-package PURLs agree exactly between scanners.** Trivy on an image
  containing `node_modules/express@4.17.1` emits `pkg:npm/express@4.17.1`. Grype
  on a repository declaring the same dependency emits `pkg:npm/express@4.17.1`.
  Byte-identical, so the existing `purl:` correlation key already joins them.
- **Trivy ignores a lock file inside an image and reads installed packages.** An
  image carrying only `/app/package-lock.json` yields no language findings; the
  same image with `node_modules/express/package.json` yields them. This is
  correct behaviour and it is load-bearing: it means an image finding is evidence
  the component is *installed*, not merely *declared*. That distinction is
  precisely §10's "whether the vulnerable component is actually deployed".
- **OS-package PURLs carry qualifiers.** Trivy emits
  `pkg:apk/alpine/libcrypto1.1@1.1.1g-r0?arch=x86_64&distro=3.9.6`. The
  `distro` qualifier tracks the base image's patch level, so an unchanged
  vulnerability in an unchanged package would change identity on a base-image
  patch bump.
- **`Result.Target` is unusable as a location.** For OS packages it is
  `"alpine:3.9 (alpine 3.9.6)"` — tag and distro version embedded. For language
  packages it is the literal string `"Node.js"`.

## Decision

### 1. Identity: the image repository, without tag or digest

An image finding's fingerprint uses the existing five-field
`FingerprintInput` with:

| Field | Value |
|---|---|
| `Category` | `container` |
| `RuleID` | empty |
| `Location` | the image **repository**, tag and digest stripped |
| `Package` | the PURL, qualifiers stripped |
| `VulnerabilityID` | the CVE |

So `ghcr.io/org/myapp:1.2.3@sha256:abc…` contributes `ghcr.io/org/myapp`.

Tag and digest are excluded because including them destroys lifecycle
continuity: every rebuild would resolve every finding and open an identical set
of new ones, and a finding whose identity changes on each build is not an
identity. The repository is excluded from nothing because omitting it entirely
would collapse two genuinely different images that happen to ship the same
vulnerable package into one finding — they are different assets, fixed
separately.

PURL qualifiers are stripped in the adapter, not in `normalizePackage`. Trivy
adding `?arch=&distro=` is trivy-specific knowledge and §7 keeps it behind the
adapter; changing the shared normalizer would re-fingerprint every stored grype
finding.

**No new fingerprint field.** `Fingerprint` joins its fields with a separator, so
a sixth field changes the joined bytes even when empty — adding one would change
the fingerprint of every finding already stored, resolving all of them and
re-creating them under new identities. Reusing `Location`, whose meaning is
already "a path within the target", leaves every existing fingerprint untouched.
Collision between an image finding and a file finding at the same string is
prevented by `Category`, which is in the fingerprint and is `container` only for
image targets.

### 2. The canonical model gains `Image`, and correlation gains nothing

`normalization.Finding` gains `Image string`, which §8 already names. It is
stored, queryable, and displayed.

`Category` is `container` for **every** finding from an image target, including
language packages. Not `dependency`: grype owns declared dependencies (§6), and
the categories differing is what makes the correlated issue *cross-domain*.
`issueSeverity` raises severity by one step only when members span two or more
categories, so `container` + `dependency` on one PURL is exactly what escalates
§9's example. Labelling image findings `dependency` would silently disable the
escalation this change exists to enable.

**No `image:` correlation key is added**, contradicting the forward-looking
comment in `internal/correlation/key.go`, which this ADR supersedes.

The reasoning: correlation asserts relationships, and "these findings are in the
same image" is a filter, not a relationship. Every finding from one image shares
the key, so the bucket is the whole scan; `linkBucket` is pairwise, so a 500-member
bucket at `DefaultMaxBucketSize` emits 124,750 links, each carrying the single
fact that the `image` column already carries. It would also form no issues,
because every member has one category and `formIssue` requires two. The work of
crossing the repository/image boundary is done by `purl:` and `cve:`, which
already exist and which measurement confirms match. "All findings in this image"
is answered by a query on the new column.

### 3. Egress: public registries only, and the SSRF hole closed first

A scan of an image reference must reach a registry. This is the first adapter
that needs egress *during* a scan of attacker-controlled input, so §14.3's
deny-by-default posture is narrowed deliberately rather than incidentally:

- **`--image-src remote`.** Trivy otherwise tries the local Docker daemon,
  containerd, and podman before the registry. A worker with a socket mounted
  would let a scan read images it was never pointed at, and would bypass the
  address policy entirely.
- **No credentials, enforced structurally.** The adapter's environment is
  already an allow-list, so `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `DOCKER_CONFIG`
  and `GITHUB_TOKEN` cannot reach the subprocess, and `HOME=/nonexistent` keeps
  it from reading `~/.docker/config.json`. Public registries only; §14.7's rule
  that workers hold no registry credentials is untouched.
- **The vulnerability database is provisioned before a job is claimed**, and the
  scan runs `--skip-db-update`. Same shape as grype's database and trivy's own
  checks bundle (ADR 012): the one moment egress is allowed is before untrusted
  content is on disk.

**`validateImage` currently performs no SSRF check.** It applies a character
allow-list and nothing else, while `validateRepository` and `validateEndpoint`
both call `checkHost`. Today that is inert, because no adapter serves the kind
and every image scan fails at dispatch. It becomes live SSRF the moment this
adapter registers: `127.0.0.1:5000/x`, `169.254.169.254/x`, or an internal
registry name would each be accepted and connected to. §14.6 requires the check.

Closing it means extracting the registry host from an image reference, which
follows the distribution specification: the first path component is a registry
when it contains `.` or `:`, or equals `localhost`; otherwise the reference is on
the default registry. The extracted host goes through the same `netguard` policy
as every other target. This lands in the same change as the adapter, not after
it.

## Alternatives considered

**Add `Image` as a sixth fingerprint field.** Cleanest to read, and it
re-fingerprints every stored finding — every open finding resolves and reopens
under a new identity, and the `findings` lifecycle that ADR 016 exists to
preserve is broken for data that has nothing to do with images. Rejected on cost,
not on taste.

**Put the image's tag or digest in the identity.** Precise about *which build* a
finding came from, and wrong about *what a finding is*: a rebuild would resolve
and recreate everything. The build is recorded on the scan, which is where "which
build" belongs.

**Use grype for images instead.** Grype scans images competently. §6's table
assigns container and image vulnerabilities to Trivy, and reassigning a domain is
a bigger change than the one being made here.

**Ask trivy for `--scanners vuln,secret,misconfig` on images.** Rejected under §6:
gitleaks owns secrets, and duplicating a domain manufactures correlation work for
no gain. Image targets get `vuln` only; filesystem targets keep `misconfig` only.

**Categorise image language-package findings as `dependency`.** Reads more
naturally, and disables the cross-domain escalation, since the grype finding is
also `dependency`. It would make the change self-defeating.

**Add the `image:` correlation key as originally sketched.** Covered above: an
n² link generator that forms no issues and asserts a fact already stored in a
column.

## Consequences

**What becomes possible.** §9's flagship example is demonstrable end to end for
the first time, and `KindImage` stops being a modelled kind that always fails.
Findings can be filtered by image. Risk scoring gains a real deployment signal,
because an image finding means installed rather than declared.

**What becomes harder.** Workers need egress to registries for image jobs, which
is a genuine widening of the trust boundary, recorded as T-49, T-50, and T-51 in
`docs/security/threat-model.md` and in `trust-boundaries.md`.

`Capabilities` needs two changes, both §24 scanner-abstraction changes and both
cheap today because nothing consumes either field yet:

- `RequiresNetwork bool` becomes `NetworkKinds []Kind`. Trivy needs egress for
  an image target and none for a filesystem one, and a single flag would have to
  claim the wider of the two for both — marking the scan that runs over
  untrusted content on disk as needing network it does not need.
- `Category Category` becomes `Categories []Category`. Trivy now covers two
  domains, and declaring only one would store a false fact about an adapter that
  emits findings in the other. The authoritative category has always been the
  one on each finding; this field declares what an adapter *can* produce.

Note what `NetworkKinds` is not: nothing reads it to impose a network policy.
It is honest metadata until the Phase 12 Kubernetes work enforces it, and
T-51 is Partial rather than Mitigated for exactly that reason.

**What we are committed to.** An image finding's identity is the repository, the
package, and the vulnerability. Changing that later is a re-fingerprinting
migration, not an edit.

**One thing the design got wrong, found by its own tests.** Putting the
repository in `Location` means the repository alone is distinguishing input, so
`Fingerprint` accepts a vulnerability that names neither a component nor an
identifier — and every such entry in one image then collapses onto that single
identity, merging unrelated defects into one finding. The hostile fixture caught
it. The adapter now refuses those entries before fingerprinting, which is the
same judgement `Fingerprint` makes for a finding carrying only a category.

**What is explicitly not solved.** Private registries stay unsupported; adding
them is a credential-handling decision, not an adapter change. Image size and
layer-expansion limits are bounded only by the shared execution timeout and
output cap — a maliciously large image is a slow scan, not a contained one, and
§14's `max artifact size` and `max archive expansion ratio` remain unenforced for
this path. Multi-architecture images collapse to one identity, because stripping
the `arch` qualifier is what keeps a rebuild on another runner from churning
identities.
