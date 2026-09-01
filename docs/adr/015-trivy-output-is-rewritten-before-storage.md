# ADR 015: Trivy output is rewritten before storage

- **Status:** Accepted
- **Date:** 2026-09-01
- **Relates to:** ADR 007 (secret redaction in raw results), ADR 012 (provisioning), ADR 014 (semgrep)

## Context

Trivy reports each misconfiguration together with the source lines that caused
it, in `CauseMetadata.Code.Lines[]`. That is genuinely useful — it is how a
person sees *why* a rule fired without opening the file.

It is also, for this scanner specifically, a direct route to storing
credentials. Infrastructure-as-code is where hardcoded secrets live. A Terraform
resource with a password in it produces a misconfiguration whose cause lines
contain that password. Measured, not assumed: a planted
`password = "hunter2-..."` appeared verbatim in the JSON, in **two** fields —
`Content` and `Highlighted`, the latter being the same line with ANSI colour, so
redacting only the obvious one leaves the secret in the document.

§15.3 forbids storing detected secret values. §8 requires raw scanner output to
be persisted verbatim. For this scanner those two cannot both hold.

ADR 007 already decided that conflict in general — §15.3 wins — and solved it
for Gitleaks with `--redact`, a flag the tool provides. Semgrep needed no
solution because unauthenticated semgrep withholds matched source on its own
(ADR 014). Trivy provides neither: there is no flag that omits cause lines from
JSON output. `--render-cause` affects only the table report.

## Decision

**The adapter rewrites trivy's output before it is persisted.** Every object
carrying a `Number` alongside a source-bearing field has `Content`,
`Highlighted`, and `Annotation` replaced with a fixed marker. What survives is
the file, the line numbers, which lines were the cause, the rule, and its
severity — everything a person acts on and everything Phase 4 fingerprints
against. What does not survive is the code.

This makes Trivy **the first adapter that modifies what it stores** rather than
only validating it, and that is a real departure worth stating rather than
burying: for this scanner, "raw" output in `scan_raw_results` is trivy's output
minus its source content. Nothing else about it is altered.

**The rewrite is structural, not textual.** The document is parsed, walked, and
re-serialised. A regex over the bytes would be guessing about a format that
nests results differently per artifact type.

**The result is asserted.** `assertNoSourceContent` re-walks the rewritten
document and discards the whole report if any source-bearing field survived. The
rewrite walks a decoded structure, so a trivy schema change that moved or
renamed those fields would make it silently miss them — and silently missing is
the failure mode that matters here. Fail closed.

**A fixed marker, not truncation.** `--max-chars-per-line`-style truncation is
not redaction: the first 40 characters of a line containing a credential can
still contain the credential.

## Alternatives considered

**Ask trivy not to emit cause lines.** No such flag exists. Checked rather than
assumed.

**Store the output verbatim and redact on the way out.** Rejected: it means the
credential is in the database, and every future consumer has to remember to
redact. §15.3 is about storage, not display.

**Drop `CauseMetadata` entirely.** Simpler, and it throws away the line numbers
a remediation needs. The cost of keeping structure while dropping content is one
walk.

**Disable the checks that surface secrets.** Misconceived: the problem is not a
class of check, it is that any misconfiguration in a file that happens to
contain a credential will quote it.

**Skip IaC scanning.** The only option that avoids the problem entirely, and it
gives up the one domain no other adapter covers.

## Consequences

- `scan_raw_results` for trivy is **not byte-identical** to what trivy emitted.
  Re-processing that stored output in Phase 4 will never see source content,
  which is intended: nothing downstream has a use for it that outweighs storing
  credentials.
- A trivy schema change that renames the source-bearing fields causes scans to
  **fail** rather than to leak. That is the correct direction to fail, and it
  means a trivy upgrade must be checked against the fixtures rather than assumed
  compatible.
- `Highlighted` is redacted alongside `Content` because it holds the same text.
  This was found by looking at the output rather than by reading the schema, and
  it is the kind of thing that a second field, added later, could reintroduce —
  which is why the assertion exists rather than trusting the field list.
- Trivy is asked for `--scanners misconfig` **only**. Grype owns dependency
  vulnerabilities and Gitleaks owns secrets (§6). Asking trivy for `secret`
  would also mean this redaction problem arriving through a second door.
- **Trivy is built with Go 1.26, not this project's 1.27.** ADR 009 builds every
  scanner with our own toolchain, and trivy v0.74.0 cannot be: it targets Go
  1.26.3 and uses `encoding/json/v2`, an experimental package whose API is not
  stable across releases. `json.SkipFunc` exists in 1.26 and was removed in
  1.27 — checked in both rather than inferred — so building it with 1.27 fails
  outright. Pinning the toolchain the scanner targets is the more honest
  reading of ADR 009 than forcing a version its source does not compile
  against, but it means this binary misses Go 1.27's standard-library fixes.
  Trivy is therefore in the govulncheck gate (ADR 013) and the image scan, so
  the cost surfaces rather than accumulating quietly.
- **Its source is fetched with a shallow clone at the tag**, unlike the other
  scanners' full clones, because a full clone of a repository that size failed
  mid-transfer. The pin is unaffected: the build still asserts `git rev-parse
  HEAD` against the commit SHA, so a repointed tag fails exactly as before.
- Adding trivy to the govulncheck gate immediately surfaced **GO-2026-4919**,
  the March 2026 supply-chain compromise of the Trivy ecosystem. It is accepted
  in `.govulnignore.yaml` with the reasoning recorded there: GitHub's advisory
  scopes it to exactly `=0.69.4` while the Go vulnerability database records an
  open-ended range, and the commit this image builds from is the signed v0.74.0
  release commit dated five months after the incident. The same attacker
  force-pushed tags in `aquasecurity/trivy-action`, which CI uses — pinned to a
  commit SHA per §16, which is why that was a non-event.
- Image targets are deliberately out of scope. They introduce a target kind that
  is not a checkout, registry credentials that trivy reads from the
  environment, and their own validation surface. ADR 012's note that a scanner's
  config dump can carry those credentials becomes live at that point, and it
  deserves its own change rather than a paragraph in this one.
