# ADR 014: Semgrep is installed from a verified wheel, not built from source

- **Status:** Accepted
- **Date:** 2026-09-01
- **Relates to:** ADR 007 (secret redaction), ADR 009 (scanners built from source), ADR 012 (provisioning)

## Context

Every scanner so far is Go, and ADR 009 builds each one from a pinned commit
with our own toolchain. Semgrep is not Go. It is a Python package wrapping
`semgrep-core`, a 311 MB OCaml binary, and building it would mean adopting an
OCaml toolchain and a Python build environment to produce an artifact we could
not meaningfully audit anyway.

Two further properties shape the decision, both measured rather than assumed:

- Its rules live in a **remote registry**. `--config p/golang` fetches over the
  network at scan time, which is egress from a process with an untrusted
  repository on disk.
- Its findings can carry **matched source**. `extra.lines` is the code the rule
  fired on, and for a credential rule that line *is* the credential — the exact
  thing §15.3 forbids storing. ADR 007 raised this when Gitleaks landed and left
  it open.

## Decision

**Install from the PyPI wheel, with that wheel's SHA-256 verified.** A
`musllinux_1_2` wheel exists for both architectures, so nothing compiles at
image build time. The digest PyPI publishes is checked before anything
executes, per architecture, resolved from `TARGETARCH`.

This is weaker than ADR 009's standard and the difference is worth naming: a
pinned commit is immutable and independently rebuildable, while a publisher
checksum only proves the artifact is the one that publisher served. ADR 009
already records that ordering. Semgrep is where the weaker option is the only
one available.

**Transitive Python dependencies are version-resolved, not hash-locked.**
Accepted deliberately, with the project owner's approval, as the shippable
first cut. Full hash-locking needs a lock covering both architectures — CI
builds amd64, developers build arm64 — and a single-platform lock fails on the
other. That is its own change.

**Rules are provisioned, not fetched during a scan.** Through the same
`scanners.Provisioner` hook grype uses (ADR 012), which is its second consumer
and the confirmation the hook was drawn at the right level. Rules are fetched
into a local directory at worker startup, before any job is claimed, and
`--config` points at that directory. `RequiresNetwork` is false.

**Matched source is asserted absent, not assumed absent.** Unauthenticated
semgrep writes `requires login` into `extra.lines` instead of the matched
line — verified against a local ruleset with a planted key, which appeared
nowhere in the output. But that follows from semgrep's *login state*, not from
any flag this adapter sets. So the adapter checks every finding before
persisting and discards the whole result if any carries source. A future
semgrep, or a token that somehow reached the subprocess, fails the scan instead
of quietly writing credentials into storage.

The environment allow-list is the first line of that defence: `SEMGREP_APP_TOKEN`
cannot be inherited because nothing unlisted ever reaches a scanner subprocess.

**`p/secrets` is deliberately not among the default rulesets.** Gitleaks owns
secret detection and §6 forbids duplicating coverage without a reason. It would
also mean reimplementing ADR 007's redaction control here, correctly, a second
time.

## Alternatives considered

**Build semgrep from source.** Requires an OCaml toolchain and a Python build
environment in the image, for an artifact nobody here can review. The pinned
commit would be honest and the audit it implies would be theatre.

**Use the official `semgrep/semgrep` image.** Pinnable by digest, which is
immutable and therefore *stronger* than a wheel hash. Rejected because it is
Debian/glibc while the worker is Alpine/musl: adopting it means changing the
base image for every scanner and re-verifying the three Go adapters against a
different libc. Worth revisiting if the worker ever moves to Debian for other
reasons.

**Run semgrep in its own container per scan.** Needs a Docker socket in the
worker — an enormous privilege escalation (§14.7), and it would make the
unfixable `docker/docker` advisories in T-33 suddenly relevant.

**Truncate `extra.lines` with `--max-chars-per-line`.** Truncation is not
redaction. The first 40 characters of a line containing a credential can still
contain the credential.

## Consequences

- **The worker image grows from 294 MB to 889 MB.** `semgrep-core` alone is
  311 MB and Python adds ~33 MB; the rest is semgrep's dependency tree. This is
  irreducible short of not shipping semgrep. The worker is not
  network-exposed and is pulled per deployment rather than per scan, which is
  why it is acceptable rather than merely tolerated.
- **pip is removed after installation.** It is a strictly better escalation tool
  than apk — it downloads and executes arbitrary code by design — so it leaves
  with the package manager the image already deletes.
- Semgrep is installed under its own prefix rather than into the system
  site-packages, and installed with `--ignore-installed`. Sharing that directory
  means pip skips dependencies apk already provides; removing pip then takes
  those with it, producing a semgrep that cannot import `packaging`. That
  happened, and was only visible because the image was run.
- **The build-time version assertion runs after the teardown**, deliberately.
  Run before it, the assertion passes against a filesystem that does not ship —
  which is how the first attempt produced a green build and a broken image.
- Semgrep needs a **writable `$HOME`**: it creates `$HOME/.semgrep` on every run
  whatever `SEMGREP_SETTINGS_FILE` says, and dies with a bare `FileNotFoundError`
  when it cannot. Its state directory is kept separate from the rules directory,
  because rules are loaded from a directory and semgrep's own state must not be
  offered to it as a rule file.
- The installation's layout is **derived from the resolved binary**, not
  hardcoded, so the adapter is testable on a developer's machine and the image
  layout can change without this package knowing.
- **govulncheck cannot see semgrep** (ADR 013 is Go-only), so trivy is the sole
  gate on this scanner. That is a real reduction in coverage relative to the
  other three adapters, and it is the strongest argument for revisiting the
  official-image option later.
