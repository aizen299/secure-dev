# ADR 013: govulncheck gates Go advisories alongside trivy

- **Status:** Accepted
- **Date:** 2026-09-01
- **Builds on:** ADR 009 (scanners built from source), ADR 012 (grype provisioning)

## Context

Trivy was SecureOps' only binary-level vulnerability gate. It is not enough,
and the gap was measured rather than suspected: on the same worker image,

| binary | trivy | govulncheck |
|---|---|---|
| gitleaks | 0 | 4 |
| syft | 0 | 2 |
| grype | 2 | 6 |

Eleven advisories trivy did not report. **Four of them had published fixes** —
two archive-parsing flaws in `mholt/archives`, an out-of-bounds read in
`klauspost/compress`, and an OpenTelemetry advisory already pinned out of grype
but left in syft. Those are not theoretical: archive parsing is precisely the
code path a secret scanner points at untrusted repositories.

The two tools are not competitors. Trivy scans OS packages, filesystems,
configuration, and container layers across every ecosystem. govulncheck knows Go
specifically: which packages a binary actually links, and which symbols survived
the linker. Running only the general tool left Go-specific findings unseen.

## Decision

**Run both.** govulncheck gates two things, with different standards:

**SecureOps' own code — zero, no exceptions.** `govulncheck ./...` in source
mode. Our dependencies are ours to choose; an advisory we cannot fix is a
dependency we should not be using. There is deliberately no accepted-risk path
for our own code.

**The shipped scanner binaries — accepted risk, with expiry.** These are
third-party and some of their advisories have no fix at any version. They are
checked in binary mode against `.govulnignore.yaml`.

govulncheck has **no ignore mechanism at all** — no flag, no file. That is a
defensible choice by its authors and an awkward one for a gate, because the only
way to get a green build with an unfixable advisory is to stop running the tool.
So the filtering is ours, and it mirrors `.trivyignore.yaml` deliberately: one
entry names one advisory on one binary, carries the reason it is accepted, and
carries an expiry date the gate enforces.

One rule beyond trivy's: **an entry that no longer matches anything is a
failure.** Stale suppressions accumulate silently and make an ignore list look
like it is doing more work than it is. If an advisory stops being reported, the
entry has to go.

## What binary mode actually proves

T-33 recorded this as an open question, and it matters because an accepted risk
rests on it. Measured with a call placed behind a runtime-false condition:

- **Source mode** is static call-graph reachability. It reported the advisory —
  a static path exists even though the call can never execute.
- **Binary mode** reports symbols present after linker dead-code elimination. No
  call graph at all. It also reported it.

So neither mode proves runtime exploitability, and binary mode is the weaker of
the two. When govulncheck reports a symbol in a third-party binary, the honest
reading is "the linker kept this code", not "an attacker can reach it". T-33's
wording — *present in the binary* — was correct, and the caution behind it was
warranted.

## Alternatives considered

**Replace trivy with govulncheck.** No. govulncheck is Go-only; trivy covers OS
packages, filesystems, IaC, and container layers. Dropping it would trade one
blind spot for a larger one.

**Suppress the unfixable advisories broadly to get green.** This is the failure
mode the decision is shaped against. A gate that passes because it was told to
ignore what it found is worse than no gate — it produces a green check that
means nothing, and §15.12 forbids exactly this.

**Run govulncheck without any exception mechanism.** Honest but unworkable: six
advisories have no fix at any version, so the gate would be permanently red and
would be switched off within a week. An exception that expires is the smaller
compromise.

**Fail only on advisories with available fixes.** Tempting and wrong: it would
silently accept every unfixable advisory forever, with no record of the decision
and no date to revisit it.

## Consequences

- **Four real vulnerabilities were fixed** as a direct result, all invisible to
  the previous pipeline. `mholt/archives` was bumped to v0.1.5 as the parent
  rather than pinning `rardecode` beneath it — v2.2.0 changes an interface
  archives v0.1.2 implements against, so forcing the child alone fails to
  compile.
- **Seven advisories remain accepted**, all `Fixed in: N/A`: five Docker Engine
  handlers in grype (also T-33) and `x/crypto/openpgp`, which is unmaintained,
  in all three scanner binaries.
- `make lint-vuln` needs the worker image, so it is not part of `make check`.
  It runs in CI's self-scan job beside `make scan-image`.
- The govulncheck version is pinned. A gate whose version floats can start or
  stop failing without anything in this repository changing (§16).
- **This gate will find more over time, and that is the point.** Every advisory
  it surfaces is one trivy would have missed.
