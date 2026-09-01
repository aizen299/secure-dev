# Normalization

Normalization is the stage that turns five scanners' incompatible output into
one canonical `Finding`. It is where SecureOps stops being a thing that runs
tools and starts being a thing that has an opinion.

CLAUDE.md §8 governs it. This document records the model and the decisions;
[fingerprinting.md](fingerprinting.md) covers identity and deduplication.

## Where it sits

```text
raw bytes (scan_raw_results)
   → parse        adapter-local types, inside internal/scanners/<name>/
   → map          adapter types → canonical Finding, still inside the adapter
   → validate     bounds, required fields, enum membership
   → fingerprint  identity (see fingerprinting.md)
   → deduplicate  exact merges; everything else becomes a link
   → persist      findings + finding_occurrences
```

Two rules shape every part of it:

**Normalization is pure.** `raw bytes → []Finding` with no I/O, no network, no
clock, no database. That is what makes it testable against fixtures, and
fixtures are the only way to test hostile input (§19).

**Mapping stays inside the adapter.** `internal/scanners/<name>/mapper.go` is
the only place that knows what a grype `match` or a trivy `Misconfiguration`
looks like. Nothing downstream imports those types or branches on a scanner's
name (§7 rules 2 and 3).

## The canonical Finding

Field groups, following §8's shape:

| Group | Fields | Notes |
|---|---|---|
| Identity | `id`, `fingerprint`, `scan_id`, `project_id` | fingerprint is the stable identity |
| Source | `scanner`, `scanner_finding_id`, `scanner_severity` | what reported it, and what it called the severity |
| Classification | `category`, `severity`, `confidence` | SecureOps' own scale |
| Description | `title`, `description`, `remediation` | prose, never used for identity |
| Location | `file`, `start_line`, `end_line` | on the occurrence, not the identity |
| Component | `package`, `package_version`, `purl` | present for dependency findings |
| Vulnerability | `cve`, `cwe`, `cvss` | present when the scanner names one |
| Lifecycle | `status`, `first_seen`, `last_seen` | §17's state machine |

`evidence` is deliberately **not** a free-text copy of the matched source. Three
adapters redact source before it ever reaches this stage (ADR 007, ADR 014,
ADR 015), and normalization must not reintroduce what they removed.

### What is not a Finding

**Syft produces no findings.** An SBOM is an inventory: nothing in it is wrong.
Forcing components into the `Finding` model to make the pipeline uniform would
be modelling convenience over meaning, and every consumer would then have to
filter them back out.

Components go to their own tables (§17's `dependencies` and `sboms`), and are
what dependency findings *join against*. This is why the pipeline is described
as producing findings **and** artifacts rather than findings alone.

## Severity

Each scanner has its own scale and none of them agrees. §8 requires one
SecureOps scale plus the original.

SecureOps: `critical` · `high` · `medium` · `low` · `info` · `unknown`

| Scanner | Their value | Ours | Note |
|---|---|---|---|
| Grype | Critical / High / Medium / Low | same | |
| | Negligible | `info` | |
| | Unknown | `unknown` | never guessed |
| Trivy | CRITICAL / HIGH / MEDIUM / LOW | same | |
| | UNKNOWN | `unknown` | |
| Semgrep | ERROR | `high` | **not** `critical` — see below |
| | WARNING | `medium` | |
| | INFO | `info` | |
| Gitleaks | *(none)* | `critical` | derived, not reported — see below |

Two mappings are judgement calls and are flagged as such rather than buried:

**Semgrep `ERROR` → `high`, not `critical`.** Semgrep's scale describes rule
severity, not exploitability: `ERROR` is its highest level and is applied
liberally across its rulesets. Mapping it to `critical` would flood the top of
the risk scale with findings that have not been assessed for exploitability,
and Phase 6's risk engine is where exposure and reachability get to raise it.

**Gitleaks has no severity at all.** A committed credential is treated as
`critical` because it is a live secret in version control. This is SecureOps'
judgement, not the scanner's, and `scanner_severity` is stored empty so the two
are never confused.

`scanner_severity` always records the original string verbatim. A future
disagreement about a mapping is then a question about the mapping rather than a
lost fact.

## Validation

Scanner output is untrusted input (§15.7) and every parse is bounded (§15.8).

- Malformed or hostile output produces a **structured parse error**, never a
  panic and never a silently dropped finding.
- A finding missing a required field is an error, not a finding with an empty
  field. "We could not read this" and "there was nothing here" must never
  collapse into each other — the same distinction the PARTIAL scan status
  exists to preserve (§13).
- Enum fields reject unknown values rather than passing them through, so a
  scanner that invents a new severity fails loudly instead of storing something
  nothing downstream understands.

## Reprocessing

Raw output is kept (§8), so normalization can be re-run when a mapper improves.
That is the reason the stage is pure: re-running it must produce the same
findings from the same bytes, and any difference must be attributable to a code
change rather than to the time of day or the state of the database.

The one asymmetry, recorded here so it is not discovered later: **trivy's stored
output is already redacted** (ADR 015), so reprocessing it will never recover
source content. That is intended.
