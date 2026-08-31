# ADR 007: Redact secret values before raw scanner output is persisted

- **Status:** Accepted
- **Date:** 2026-08-31

## Context

Two rules in CLAUDE.md collide the moment a secret scanner is added, and the
Gitleaks adapter is the first code that has to resolve the collision.

**§8** requires that raw scanner output be persisted verbatim, size-capped, so
results can be re-parsed when normalization improves and a disputed finding can
be traced back to what the scanner actually said. "Never discard raw results."

**§15.3** forbids storing or logging secret values, and is explicit about this
exact case: "Redact secret values in Gitleaks/Trivy findings — store a location
and a hash, not the secret."

Gitleaks' default JSON output contains the credential in plaintext, twice:

```json
{
  "RuleID": "github-pat",
  "File": "creds.txt",
  "StartLine": 2,
  "Secret": "<the actual token>",
  "Match":  "<the actual token>",
  "Fingerprint": "creds.txt:github-pat:2"
}
```

Persisting that verbatim would turn the SecureOps database into a store of live
credentials harvested from every repository the platform has ever scanned. It
would also mean a SecureOps compromise escalates directly into a compromise of
every customer's third-party systems — the single worst outcome available to
this architecture, and one created entirely by the tool meant to prevent it.

The rules cannot both be followed literally. One has to give.

## Decision

**§15.3 wins. Secret values are never persisted, never logged, and never
returned by the API.**

Concretely, for any adapter whose output can contain a credential:

1. **Redact at the source.** Gitleaks is invoked with `--redact`, so the value
   is replaced with `REDACTED` inside the scanner process. The plaintext never
   enters SecureOps' memory at all, which is a stronger guarantee than
   scrubbing it after the fact.

2. **Verify before persisting.** The adapter parses the report and asserts that
   every finding's `Secret` and `Match` are redacted. If any is not, the
   adapter **discards the output and fails the scanner result**. This is what
   makes the control hold when it matters: if a future gitleaks release renames
   the flag, changes its default, or adds a field carrying the value, the
   pipeline fails closed instead of silently persisting credentials.

   The two fields are checked differently, and getting this wrong once already
   broke a real scan:

   - `Secret` is the bare credential, so under `--redact` it is **exactly**
     `REDACTED`. The check is an equality test.
   - `Match` is the matched text *with its surrounding context*, so gitleaks
     substitutes the marker inside it: `api_key = "REDACTED"` is correctly
     redacted output. The check is that the marker is **present**.

   The first implementation applied the equality test to both. It passed every
   fixture and every synthetic repository, then failed closed on the first real
   one — `generic-api-key`, the most common rule there is, produces a `Match`
   with context, so every finding was discarded and the scan reported as
   failed. A survey of 22 findings from a public repository of planted secrets
   confirmed the shapes: `Secret` was exactly the marker every time, `Match`
   contained it every time, sometimes with context.

   The residual risk in the `Match` check is a line holding two secrets where
   only one was substituted. Each finding's `Match` corresponds to its own
   secret, so that is not a shape gitleaks produces.

3. **Keep everything else.** Rule ID, file, line, column, entropy, commit,
   author, date, and gitleaks' own stable `Fingerprint` all survive redaction.
   A finding remains fully actionable: an engineer is told *which* secret rule
   fired *where*, which is what they need in order to go and rotate it.

§8's "verbatim" therefore means **verbatim except for values §15.3 forbids
storing**. That is a narrowing of §8, and it is recorded here rather than
applied silently.

### Why a hash is not stored either

§15.3 says "store a location and a hash, not the secret." SecureOps stores the
location and gitleaks' `Fingerprint`, which is `file:rule:line` (or
`commit:file:rule:line` for history scans) — not a hash of the secret.

A hash of a credential is not a safe artifact. Most detected secrets are drawn
from a small, enumerable space — a 20-character AWS key ID, a 40-character
GitHub token with a fixed prefix — so an unsalted digest is recoverable by brute
force and is, in practice, the secret. A salted digest would resist that but
could no longer be compared across scans, which is the only reason to want one.

The purpose a hash would serve is lifecycle continuity: recognising the same
finding across re-scans. `Fingerprint` already does that, without deriving
anything from the secret's value. So the location is stored, the hash is not,
and §15.3's intent is met more safely than its letter.

Phase 4 revisits this when the canonical fingerprint is designed; that ADR must
not reintroduce a secret-derived input.

## Alternatives considered

**Persist the unredacted output and restrict access to it.** Rejected. It makes
the database a credential store and moves the problem to access control, which
is exactly the mitigation §15.3 declines to rely on. It would also mean a
database backup, a replica, or a support engineer's query is a credential
disclosure.

**Persist unredacted output encrypted at rest.** Rejected for now. It sounds
rigorous but buys little: the decryption key lives in the same deployment, so
the compromise scenario is largely unchanged, and it introduces key management,
rotation, and recovery — real complexity in exchange for retaining data nobody
should want. If a use case for the plaintext ever emerges, this is the option to
revisit, and it needs its own ADR.

**Store nothing at all for secret scanners.** Rejected as an overcorrection. It
would lose the location, the rule, and the lifecycle, making detected secrets
untrackable across scans — the finding would be reported once and then forgotten
each re-scan.

**Scrub after parsing rather than using `--redact`.** Rejected as strictly
weaker. It requires the plaintext to pass through SecureOps' memory, where it
can reach a log line, a panic message, an error string, or a heap dump. Using
the scanner's own redaction keeps the value out of the process entirely, and the
verification step in (2) still catches the case where it fails.

## Consequences

- Raw gitleaks output is persisted with `Secret` and `Match` as `REDACTED`.
  Re-parsing works; recovering the credential does not, by design.
- A gitleaks upgrade that breaks redaction fails the scan rather than leaking.
  The verification is a security control, so it is covered by a test that
  removes it and confirms the test fails.
- **A fail-closed control has a cost that has to be paid attentively.** Being
  too strict does not fail safe in the way it first appears: it discards real
  findings and reports the scan as broken, which is its own kind of false
  reassurance. The check must be exactly as strict as the guarantee it is
  making, and it must be validated against real scanner output rather than only
  against fixtures, because fixtures encode what the author already believed.
- The same treatment is required for **Trivy's secret scanner** when that
  adapter lands, and for any future adapter that can surface a credential.
  §15.3 is not gitleaks-specific, and the next adapter must not have to
  rediscover this reasoning.
- Semgrep is a related but distinct case: its output embeds matched source
  lines, which can contain a secret incidentally. That is a Phase 3b problem for
  the Semgrep adapter, and it is not solved by this ADR. It is recorded as a
  known limitation rather than left implicit.
- SecureOps can report *that* a credential leaked and *where*, but can never
  show the value. That is the correct trade: the remediation for a leaked secret
  is to rotate it, which never requires reading it.
