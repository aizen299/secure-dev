# Risk Engine

The risk engine answers one question: **given everything SecureOps knows, how
much should this project worry?**

It is the last of the three deterministic engines and the one §10 constrains
most tightly. This document is the specification: the formula, every factor's
derivation, every default weight, and the properties the tests enforce. It
exists **before** the implementation, as §10 and §21 require — the formula is
the project's core innovation and the part most likely to drift.

The decision and its rationale are in
[ADR 019](../adr/019-risk-scoring-and-aggregation.md).

## Position in the pipeline

```text
Normalization → Deduplication → Correlation → RISK → Remediation → Policy
```

Risk consumes canonical findings, correlated issues, and the project record. It
produces a score per finding and a score per project. Like normalization and
correlation, it is **pure**: same inputs, same score, always — no I/O, no clock,
no database, no network. That is what makes the monotonicity and
factor-isolation tests possible at all.

**No AI, no LLM, no heuristic model influences the score** (§10). AI may explain
a score; it may never produce one.

## The formula

Per finding:

```text
risk = SeverityWeight × Exploitability × Exposure × AssetCriticality × Confidence
```

Per project:

```text
total = max(risk) + λ × (Σ risk − max(risk))        λ = 0.15
score = 100 × (1 − e^(−total ÷ K))                  K = 200
```

The multiplicative per-finding form is §10's. Every factor is a **multiplier
around a documented neutral point**, so a factor with no information contributes
exactly 1.0 and cannot silently drag a score up or down.

### Why not a weighted sum of factors

A sum lets a high value in one factor compensate for a low value in another: a
critical severity in a development sandbox would still score highly. The
multiplicative form makes the factors *gates* — a finding that is severe but on
a throwaway asset is genuinely lower risk, and the arithmetic says so. The
worked examples below show a worst-case critical scoring 81.3 and the *same
severity* in a low-criticality sandbox scoring 10.0.

## Factor 1 — Severity Weight

The base magnitude. **Not** a linear rank, and not a nearly-linear one either:
the gap between critical and high must be larger than the gap between low and
info, or the scale is a rank in disguise.

| Severity | Weight | Reasoning |
|---|---|---|
| `critical` | 100.0 | |
| `high` | 30.0 | a critical is worth more than three highs — the step is deliberately steep, because a scale where enough highs outrank a critical is a scale that rewards counting |
| `medium` | 8.0 | |
| `unknown` | 5.0 | above `low` on purpose — an unassessed finding deserves more attention than one assessed as unimportant, matching `Severity.Rank()` |
| `low` | 1.0 | |
| `info` | 0.05 | never zero: an informational finding is still a finding, and zero would make it invisible to aggregation |

The spread is roughly geometric (×2000 from `info` to `critical`) rather than
the ×100 an ordinal scale would give. That is the non-linearity §10 asks for,
stated as a ratio rather than asserted as a word.

**Which severity.** Where a finding belongs to a correlated issue whose severity
was escalated, the **issue's** severity is used. That is what the escalation is
for — correlation already determined that cross-domain corroboration makes the
combination worse than its parts (ADR 017), and re-deriving it here would
compute the same signal twice.

## Factor 2 — Exploitability

How likely anyone is to exploit this, as opposed to how bad it would be.

Derived from threat intelligence (ADR 018), currently EPSS alone. Range
**[0.5, 1.5]**, neutral 1.0.

```text
Exploitability = 0.5 + EPSS.Percentile        (when a signal is available)
Exploitability = 1.0                          (when none is)
```

Three deliberate choices here, each one a rule §10 or ADR 018 imposes:

**Percentile, not probability.** EPSS probabilities are absolute and heavily
skewed toward zero — 0.073 is a real value for a critical vulnerability.
Multiplying a severity weight by 0.073 would erase the findings that matter
most. Percentile is the calibrated *relative* signal and is near-uniform by
construction, which is what makes it usable as a multiplier. **EPSS is never
multiplied directly into a severity weight** (ADR 018 §5).

**Absence is neutral, never low.** A finding with no EPSS scores at 1.0, and the
explanation records that the signal was unavailable. Substituting a low value
would be scoring "we do not know" as "nobody is exploiting this" — the same
error the `*EPSS` pointer exists to prevent.

**Positive evidence of low likelihood does lower risk.** A finding at percentile
0.0 scores 0.5, below the neutral 1.0 of a finding with no data. This is
intentional and is not the same as the previous rule: we have measured evidence
that this is rarely exploited, which is genuinely different from having none.

### Future signals

`Exploitability` is the aggregation point for every threat-likelihood signal,
not an EPSS field with a different name. When CISA KEV lands, a
known-exploited finding takes the top of the range regardless of percentile —
a vulnerability with observed exploitation in the wild is not a probability
question. CVSS v4 Exploit Maturity joins the same way. Neither requires
reshaping the formula.

## Factor 3 — Exposure

Where the finding lives. From the project record (`Environment`,
`InternetFacing`) — fields Phase 1 added for exactly this, whose comments
already cite §10.

| Environment | Base | |
|---|---|---|
| `production` | 1.0 | |
| `staging` | 0.6 | |
| `development` | 0.3 | a finding in a sandbox is not the same finding |

Multiplied by **1.5** when `InternetFacing` is true.

Range **[0.3, 1.5]**, neutral at production-but-not-internet-facing.

**This is project-level, not finding-level, and that is a stated limitation.**
Real exposure is a property of the deployed component: whether *this* vulnerable
package is reachable from *this* internet-facing service. Answering that needs
reachability analysis and SBOM component storage, neither of which exists. The
project record is a coarse but honest proxy, declared by a human rather than
inferred.

## Factor 4 — Asset Criticality

How much the project matters. From `Project.Criticality`.

| Criticality | Multiplier |
|---|---|
| `critical` | 1.5 |
| `high` | 1.2 |
| `medium` | 1.0 |
| `low` | 0.7 |

Declared configuration, not derived. That is the point: only the operator knows
whether a service is load-bearing, and a platform that guessed would be
confidently wrong.

## Factor 5 — Confidence

How much SecureOps trusts the finding to be real. Range **[0.5, 1.0]** — it can
only ever *reduce* risk, never inflate it, because uncertainty is not evidence.

| Confidence | Multiplier |
|---|---|
| `high` | 1.0 |
| `medium` | 0.75 |
| `low` | 0.5 |

**Corroboration raises the level, not the multiplier.** A finding reported
independently by two or more distinct scanners moves up one step —
`low → medium → high`, capped at `high` — before the table is applied.

This is the seam ADR 017 reserved: cross-domain corroboration raises *severity*
in correlation, same-domain scanner agreement raises *confidence* here. Two
scanners agreeing that a package is vulnerable is evidence the finding is real,
not evidence it is worse. Keeping them apart is what stops one signal being
counted twice.

### The independence caveat, stated rather than assumed

The rule above treats every pair of scanners as equally independent, and they
are not. Grype and Trivy both derive dependency vulnerabilities from overlapping
public advisory feeds, so the two of them agreeing on a CVE is substantially
one database consulted twice — the same observation `issueSeverity` already
records as its reason for capping escalation at one step. Gitleaks and Semgrep
independently flagging the same line is much stronger evidence, because the two
reached it by unrelated methods.

The engine does **not** currently distinguish these cases, and the one-step cap
is what keeps the error bounded rather than compounding. Fixing it properly
means each adapter declaring its evidence family (§7's "add a capability flag on
the adapter"), never a scanner-name conditional inside `internal/risk/`, which
§7.2 and §25.3 forbid outright. That is an interface change and therefore needs
its own ADR; until then the overstatement is documented here and in
[the limits below](#what-this-engine-does-not-do) rather than hidden in a weight.

## Project aggregation

```text
total = max(risk) + λ × (Σ risk − max(risk))     λ = 0.15 (configurable)
score = 100 × (1 − e^(−total ÷ K))               K = 200  (configurable)
```

**Why max-dominant rather than a plain sum.** §10 requires that adding a finding
never reduces the score, which rules out an average outright — adding a low
finding to a project full of criticals lowers the mean. A plain sum is monotonic
and was the first design here, but it has a defect that only shows up
arithmetically: with any bounded severity spread, **enough trivia outranks a
catastrophe**. Under the previous draft's weights, 500 informational findings
scored 71.3 while the single worst finding the model can express scored 56.7.
That is not a tuning error; summation says volume and severity are
interchangeable, and for a security score they are not.

Max-dominant aggregation makes the worst finding the floor and treats everything
else as accumulating pressure on top of it. λ = 0.15 sets how much the tail
matters: high enough that a hundred mediums (47.0) clearly outrank one medium
(3.9), low enough that ordinary noise cannot impersonate a crisis.

**Volume still crosses severity eventually, and the crossover is stated rather
than claimed away.** Against one worst-case finding (335.25), a project of
otherwise-neutral findings draws level at:

| Severity of the crowd | Findings needed to equal one worst-case critical |
|---|---|
| `info` | ~44,700 |
| `low` | ~2,230 |
| `medium` | ~274 |

The first two are volumes at which the volume *is* the finding. The third is
reachable by a real project, and it is a deliberate judgement rather than an
oversight: 274 unfixed production mediums are a comparable security position to
one internet-facing critical under active exploitation. λ is the dial that sets
that exchange rate, and this table is what makes it arguable — the previous
plain-sum design put the `info` crossover at **335**, which was not arguable at
all.

**Monotonicity is proved, not sampled.** For any new finding with risk `r ≥ 0`
and λ ∈ [0, 1]:

- if `r ≤ max`, the total rises by exactly `λr ≥ 0`;
- if `r > max`, the new total is `r + λΣ` against the old `max(1−λ) + λΣ`, and
  `r > max ≥ max(1−λ)`, so it rises.

`score` is strictly increasing in `total`, so it never falls. The property test
exists as a regression guard on the implementation, not as the argument.

**Which findings.** Live ones only — `open`, `reopened`, `acknowledged`,
`in_progress`. Resolved, false-positive, and ignored findings score zero, the
same set correlation operates on. A dismissed finding contributing to risk would
mean a human decision never actually lowered the number.

**Reading the scale.** Computed from the factor tables above, not estimated:

| Situation | total | score |
|---|---|---|
| one medium, production, no internet, medium criticality, high confidence, no EPSS | 8.0 | 3.9 |
| one **critical**, development, low criticality, no EPSS | 21.0 | 10.0 |
| one **critical**, production, internet-facing, critical asset, EPSS p99 | 335.3 | **81.3** |
| ten such criticals | 787.8 | 98.1 |
| fifty lows, all neutral | 8.4 | 4.1 |
| one hundred mediums, all neutral | 126.8 | 47.0 |
| five hundred informational, all neutral | 3.8 | **1.9** |

Rows two and three are the same severity in different contexts, 71 points apart:
that is the contextual scoring §10 is actually asking for. Rows three and seven
are the defect this design exists to fix. Row four is saturation behaving
correctly — past a point, "worse" stops being a useful distinction.

**K is calibration, and calibration is judgement — so it is anchored.** K is not
chosen by feel; it is derived from one stated commitment: *a single worst-case
finding should score about 80* — unambiguously bad, visibly not maximal, leaving
the top of the scale for projects that have several. Solving
`100 × (1 − e^(−335.25 ÷ K)) = 80` gives K = 208.3, rounded to **200** for a
round default, which lands the anchor at 81.3.

Change the anchor and K follows arithmetically. That is the difference between a
calibrated constant and a magic number: the judgement is in the anchor, stated
in one sentence and arguable on its own terms, rather than in the constant.

## Weights are configuration

Every number in this document is a default in one `Weights` struct, not a
constant scattered through the scoring code. §10 requires it, and the practical
reason is that re-tuning must be a config change with a diff, not an
archaeology exercise across a package.

The engine takes weights as an argument. Tests supply their own, which is what
makes factor-isolation testing possible.

## Properties the tests enforce

Mandatory per §10, and each maps to a specific failure this design could have:

1. **Determinism** — same inputs, same score, always.
2. **Monotonicity** — adding any finding never lowers the project score. The
   property an average would break.
3. **Factor isolation** — varying one factor with all others fixed moves the
   score in the expected direction and only that direction. Catches a factor
   accidentally reading the wrong field.
4. **Boundary conditions** — empty project scores 0; every enum value has a
   weight; no combination produces NaN, a negative score, or one above 100.
5. **Neutral absence** — a finding with no EPSS scores exactly as it would with
   the exploitability factor removed. This is the test that stops "unknown"
   drifting into "low".
6. **Dismissed findings score zero** — a false positive contributes nothing.
7. **No double counting** — a finding in an escalated issue is scored once at
   the escalated severity, not escalated and then boosted again through
   confidence.
8. **Severity beats volume at realistic scale** — one worst-case critical
   outscores tens of thousands of informational findings, and the measured
   crossover stays where the table above says it is. The regression test for
   the defect that produced this design.

## What this engine does not do

§10 lists contextual factors this design cannot honestly provide yet. Naming
them is better than implying the score already accounts for them:

- **Reachability** — whether the vulnerable code path is actually callable. No
  scanner provides it; correlation already refuses to guess it (ADR 017).
- **Whether the component is actually deployed** — needs SBOM component storage.
  Syft's output is still an unparsed blob, so "is this dependency in the build"
  is unanswerable.
- **Vulnerability density** — needs a size denominator (lines, components) that
  nothing currently records.
- **Known-exploit presence** — CISA KEV is not yet ingested. The slot exists in
  `Exploitability` and takes one signal to fill.
- **Scanner independence** — corroboration counts distinct scanner names, not
  distinct evidence sources. See the caveat under Confidence above.
- **Coverage** — the engine scores the findings it has, and cannot know what a
  failed scanner would have found. A `PARTIAL` scan therefore produces a
  *lower* score, which is indistinguishable from an improvement by arithmetic
  alone. The engine does not compensate, because inventing findings would be
  worse; instead every stored score carries the status of the scan it was
  computed for, and the API exposes it as `scan_status` and `complete`. §12's
  gate must read that, not the number alone (threat model T-42).

Affected-component count and finding count *are* reflected, but through the
aggregate tail rather than as explicit terms.

## Explainability

A score with no breakdown is an assertion. Every score carries the factor values
that produced it and, where a factor was neutral for lack of data, says so:

```text
risk 335.25 = severity 100.0 (critical, escalated from high by issue cve:CVE-…)
            × exploitability 1.49 (EPSS percentile 0.99, grype, 2026-08-30)
            × exposure 1.5 (production, internet-facing)
            × criticality 1.5 (critical)
            × confidence 1.0 (high, corroborated by grype and trivy)
```

This is what §12 needs to explain a gate result, what §11 needs to prioritise
remediation, and what makes the number arguable rather than oracular.
