# ADR 018: Threat intelligence is its own attribute, not a scanner field

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

Phase 6 implements §10's risk formula:

```text
Risk = Severity Weight × Exploitability × Exposure × Asset Criticality × Confidence
```

Four of those five factors have real inputs today. Severity is normalized on
every finding. Exposure and Asset Criticality come from the project record,
which has carried `Environment`, `Criticality`, and `InternetFacing` since
Phase 1 — the fields were added for exactly this. Confidence is on every
finding, and correlation now adds cross-domain corroboration on top.

**Exploitability is the exception, and it is the factor §10 cares most about.**
The canonical `Finding` carries `CVSS` and nothing else. CVSS describes how bad
a vulnerability would be if exploited; it says almost nothing about whether
anyone is exploiting it. Deriving "exploitability" from CVSS would make the
formula five terms doing four terms' work, and §10 explicitly warns against
naive severity-to-number mapping.

EPSS — the FIRST.org Exploit Prediction Scoring System — is the calibrated
answer to the question CVSS does not ask. Grype already emits it and the
adapter currently discards it:

```json
"epss": [{ "cve": "CVE-2026-42508", "epss": 0.07314,
           "percentile": 0.93929, "date": "2026-08-30" }]
```

The temptation is to add an `EPSS float64` beside `CVSS` and move on. That
would be wrong in three separate ways, and each of them is the reason this ADR
exists.

**A single float destroys the distinction between "low" and "unknown".** A
finding with no EPSS data would score 0.0, which reads as "certainly not
exploited" — the strongest possible claim, made from an absence of data. This
is the same error §8 already rejects for severity, where `unknown` is a
distinct value precisely because "we do not know" and "it does not matter" are
different claims.

**A single float destroys provenance.** EPSS is a model output with a date, not
a constant. The value above was observed on 2026-08-30 and will be different
next week. A number with no source and no observation time cannot be audited,
cannot be aged out, and cannot be reconciled when two providers disagree.

**A single float invites the wrong arithmetic.** EPSS probabilities are
absolute and small: the example above is 0.073 — a 7.3% chance — while sitting
at the 93.9th percentile. Multiplying a CRITICAL finding's weight by 0.073
would erase it. Anyone reaching for `cvss * epss` produces a scoring function
that systematically buries the most dangerous findings.

## Decision

**1. Threat intelligence is a structured attribute on the canonical Finding,
not a scanner field.**

```go
type ThreatIntel struct {
    EPSS *EPSS
}

type EPSS struct {
    Probability float64   // 0..1, the absolute likelihood
    Percentile  float64   // 0..1, the rank among all scored CVEs
    Source      string    // provenance: where this value reached us from
    ObservedAt  time.Time // the model date the value came from
}
```

`ThreatIntel` is a container with one member today and room for the signals
already known to be coming: CISA KEV (known-exploited), and CVSS v4 Exploit
Maturity. Each arrives as a sibling field, not as a reshaping.

**2. Missing is `nil`, never zero.** `*EPSS` is a pointer for exactly this
reason. "No EPSS data for this vulnerability" and "EPSS says essentially nobody
is exploiting this" are opposite claims, and a `float64` zero value cannot tell
them apart. Every consumer must branch on availability before reading a number.

**3. Provenance is mandatory.** `Source` and `ObservedAt` are validated as
required whenever an `EPSS` is present. A threat-intelligence value whose
origin and age are unknown is not evidence; it is a number.

**4. The model does not assume Grype.** Grype supplies the first values because
it already has them, but nothing in `normalization` names Grype, and nothing
about the shape presumes a scanner is the source at all. A future direct EPSS
client, a KEV feed, or an enrichment stage populates the same structure and
records itself in `Source`. Enrichment that performs I/O cannot live in
`normalization`, which is pure by contract — it will be its own stage.

**5. Constraints on Phase 6, recorded here so the risk engine honours them.**

- EPSS is a **threat-likelihood** input. It is not a severity, not a risk
  score, and must never be presented as either.
- **EPSS must not be multiplied directly by CVSS.** See the arithmetic above.
  Exploitability is derived from the available threat-likelihood signals as a
  bounded factor, and the derivation is documented in
  `docs/architecture/risk-engine.md` before it is implemented.
- A finding with no EPSS must not be scored as though EPSS said "low". The
  absence of a signal is handled explicitly, not by substituting a value.

**6. Grype's own `risk` field is ignored.** Grype emits `"risk": 6.6191` — its
own composite score. Using it would mean two different formulas producing two
different numbers both called risk, and §10 makes SecureOps' risk a single
deterministic function with documented weights. It is discarded deliberately,
not overlooked.

## Alternatives considered

**`EPSS float64` on Finding.** Rejected on all three grounds above: it cannot
express unavailability, carries no provenance, and invites `cvss * epss`.

**Store the whole scanner EPSS array verbatim.** Rejected. Raw scanner shapes
must not reach the core engines (§7 rule 3), and the array is grype's
representation of a one-to-many advisory mapping, not a fact about the finding.
The adapter resolves it to at most one value; resolution is adapter work.

**Populate `CVE` correctly first, then match EPSS on it.** Rejected as a change
that pays for a naming fix with real damage. `mapper.go:61` sets
`CVE: m.Vulnerability.ID`, so a GHSA advisory currently lands in a field named
`CVE`. That is genuinely wrong. But that field is a fingerprint input, so
changing which value it holds would re-fingerprint every stored grype finding
and orphan its entire lifecycle history — the precise failure fingerprinting
exists to prevent. EPSS association therefore happens inside the adapter using
`relatedVulnerabilities`, with no fingerprint impact. **The naming inaccuracy is
recorded as a known issue rather than silently repaired**; fixing it needs a
migration that re-fingerprints deliberately, which is its own decision.

**Derive exploitability from CVSS alone and skip EPSS.** Rejected. CVSS and
severity are strongly correlated, so the factor would add little independent
signal while making the formula look more contextual than it is.

## Consequences

**Easier.** Exploitability becomes a real factor rather than a restatement of
severity. Adding KEV or exploit maturity is a field on an existing struct.
A stale threat-intelligence value is detectable, because every value carries its
date. Two providers disagreeing is a resolvable question, because every value
carries its source.

**Harder.** Every consumer must handle `nil`. That is the intended cost — it is
what stops "unknown" from silently becoming "low", and the compiler enforces it
in a way a `float64` never could.

**Committed to.** Threat intelligence never becomes a severity. Missing data is
never a zero. Provenance is never optional. The risk engine does not multiply
EPSS by CVSS, and the absence of a signal is handled explicitly rather than
defaulted.

**Known issue, deliberately not fixed here.** `Finding.CVE` holds whatever
identifier the scanner reported, which for grype is often a GHSA rather than a
CVE. The field name overstates what it contains. Correcting it requires a
deliberate re-fingerprinting migration.
