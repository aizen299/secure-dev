# ADR 016: The canonical Finding model and fingerprint strategy

- **Status:** Proposed — awaiting the project owner's approval before implementation
- **Date:** 2026-09-01
- **Relates to:** ADR 007, ADR 014, ADR 015 (redaction), ADR 010 (degraded coverage)
- **Detail:** [normalization.md](../architecture/normalization.md), [fingerprinting.md](../architecture/fingerprinting.md)

## Context

Five scanners now produce raw output that nothing converts into findings.
CLAUDE.md §24 lists "changing the canonical finding model, fingerprint strategy,
or dedup semantics" as requiring an ADR and approval **before** implementation,
and §1 requires the fingerprint strategy to be documented in
`docs/architecture/` before Phase 4 code exists. This ADR and the two documents
beside it exist to satisfy that, not to record something already built.

## Decision

**The fingerprint is computed by SecureOps, not taken from the scanner.**
Checked rather than assumed: gitleaks' fingerprint is `file:rule:**line**` and
so changes whenever code above a secret is edited; semgrep's is withheld as
`requires login` in our unauthenticated configuration (ADR 014); trivy has none.
One is unstable in exactly the way §8 forbids and the others do not exist.

```text
fingerprint = SHA256(category ␟ rule_id ␟ location ␟ package ␟ vulnerability_id)
```

Joined with `0x1f`, which no normalized field may contain, because plain
concatenation lets `"ab"+"c"` and `"a"+"bc"` collide.

**Line numbers are excluded from identity** and recorded on occurrences. This is
the decision the whole design turns on: a fingerprint containing a line number
restarts a finding's history on every edit above it.

**Scanner name is excluded from identity.** Two scanners reporting the same CVE
on the same package are reporting one problem, and §9's correlation depends on
seeing that. Rule-based findings stay scoped to their scanner anyway, because
`rule_id` is scanner-specific — the behaviour falls out of the formula rather
than needing a special case.

**Only exact fingerprint matches merge.** Likely duplicates, related findings,
and independent findings are linked with a confidence value and kept separate,
per §8's four relationships and §25.5's prohibition on merging by similarity.

**Syft output does not become findings.** An SBOM is an inventory; nothing in it
is wrong. Components go to their own tables and are what dependency findings
join against.

## Alternatives considered

**Use each scanner's own fingerprint where available.** Rejected on evidence:
unstable where present, absent or withheld elsewhere. It would also make
identity depend on scanner internals that change between versions.

**Include the line number, and accept churn.** Rejected. It makes the lifecycle
states in §17 — acknowledged, resolved, reopened — meaningless, because every
finding is new after any edit. The states are the point of having a fingerprint.

**Include the scanner name.** Simpler and it forecloses cross-scanner
deduplication permanently, which is most of what §9 exists to do.

**Hash the secret value to distinguish co-located secrets.** Impossible and
undesirable: §15.3 means the value is never stored, so there is nothing to hash.

**Normalize SBOM components into findings.** Rejected: uniformity bought by
modelling something as a problem when it is not one, with every consumer then
filtering them back out.

## Consequences

- **Two instances of the same rule in one file share a fingerprint.** Two
  hardcoded credentials in `config/settings.py` both matching `github-pat` are
  one finding with two occurrences. Accepted deliberately: the remediation is
  identical, the occurrences carry the individual lines, and the alternative
  sacrifices lifecycle continuity for every finding to separate a minority.
  This is the most significant limitation in the design and is stated in
  fingerprinting.md rather than left to be discovered.
- Findings need two tables — `findings` for identity and `finding_occurrences`
  for per-scan sightings — which is the shape §17 already anticipates.
- Two severity mappings are SecureOps' judgement rather than the scanner's:
  semgrep `ERROR` becomes `high` rather than `critical`, and gitleaks findings
  become `critical` despite gitleaks having no severity at all. Both are
  recorded in normalization.md with reasoning, and `scanner_severity` always
  keeps the original so a disagreement is about the mapping and not about a
  lost fact.
- Normalization is pure, so re-running it over stored raw output must produce
  identical findings. Any difference is a code change, by construction.
- **Trivy's stored output is already redacted** (ADR 015), so reprocessing it
  can never recover source content. Intended, and noted so nobody later reads
  the absence as data loss.
