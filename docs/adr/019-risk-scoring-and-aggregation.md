# ADR 019: Risk is a max-dominant sum of gated finding scores

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

§10 gives the formula and the constraints:

```text
Risk = Severity Weight × Exploitability × Exposure × Asset Criticality × Confidence
```

pure and deterministic, normalised to 0–100, weights as configuration, no naive
severity-to-number mapping, no AI influence, and unit tests covering boundary
conditions, factor isolation, and **monotonicity — adding a finding must never
reduce risk**.

The formula settles the per-finding shape. It leaves three decisions that
actually determine whether the number means anything, and each has an obvious
wrong answer that would pass a casual review.

**How findings aggregate into a project score.** §10 says the score is
normalised to 0–100 and that adding a finding must never reduce it. The natural
reach is an average — and an average breaks the monotonicity requirement
outright, because adding a low-severity finding to a project full of criticals
lowers the mean. The requirement and the obvious implementation are in direct
conflict, and that conflict is not called out anywhere in the spec.

**How EPSS becomes a factor.** ADR 018 captured it and explicitly forbade
multiplying it into a severity weight: probabilities are small enough that a
critical finding scaled by 0.073 disappears. So "Exploitability" cannot be the
EPSS probability, and what it *is* has to be decided here.

**Where correlation stops and risk starts.** Correlation escalates an issue's
severity when findings span domains. If risk also rewards corroboration, the
same evidence is counted twice and the formula quietly stops being the one §10
documents.

## Decision

**1. Every factor is a multiplier around a documented neutral point.**

Each factor has a stated range and a neutral value of 1.0. A factor with no
information contributes exactly 1.0 and cannot drag the score in either
direction. This is what makes factor-isolation testing meaningful: hold four
factors at neutral, vary the fifth, and the score moves only as that factor
predicts.

**2. Exploitability is derived from EPSS percentile, not probability.**

```text
Exploitability = 0.5 + EPSS.Percentile   (signal available)
Exploitability = 1.0                     (no signal)
```

Percentile is the calibrated relative measure and is near-uniform by
construction, so it behaves as a multiplier. Probability is absolute and skewed
toward zero, so it behaves as an eraser.

Absence is neutral, never low — scoring "we do not know" as "nobody is
exploiting this" is the exact error ADR 018's pointer exists to prevent.
Measured low likelihood (percentile 0.0 → 0.5) *does* reduce risk, because
evidence of safety is not the same as absence of evidence.

`Exploitability` is the aggregation point for future signals — CISA KEV, CVSS
v4 Exploit Maturity — not an EPSS field under another name.

**3. Severity weights are geometric, not ordinal.**

`critical 100 · high 30 · medium 8 · unknown 5 · low 1 · info 0.05`

A ×2000 spread from `info` to `critical`. §10 forbids a "naive severity-to-number
mapping", and a nearly-linear table (10/6/3/2/1) is that mapping wearing
different numbers — it silently asserts that six mediums are worse than one
critical. `unknown` sits above `low`, matching `Severity.Rank()`: unassessed is
not the same as assessed-and-unimportant.

**4. Project score is a max-dominant sum, saturated.**

```text
total = max(risk) + λ × (Σ risk − max(risk))     λ = 0.15
score = 100 × (1 − e^(−total ÷ K))               K = 200
```

The worst finding sets the floor; everything else is accumulating pressure above
it. Monotonic by proof rather than by sampling: if `r ≤ max` the total rises by
`λr`, and if `r > max` it rises by `r − max(1−λ) > 0`, for any λ ∈ [0, 1].

**5. K is derived from a stated anchor, not chosen.**

The anchor: *one worst-case finding should score about 80.* Given the factor
tables, that finding's risk is 335.25, so
`100 × (1 − e^(−335.25 ÷ K)) = 80` gives K = 208.3, rounded to 200. Change the
anchor and K follows arithmetically — the judgement lives in one arguable
sentence rather than inside a constant.

**6. Correlation owns severity; risk owns confidence.**

A finding in an escalated issue is scored at the **issue's** severity, once.
Same-domain scanner agreement raises *confidence* by one level before the
confidence table is applied. This is the seam ADR 017 reserved in advance:
cross-domain corroboration means "worse", same-domain agreement means "more
likely to be real". Counting either twice would inflate exactly the findings a
security team is most likely to be looking at.

Corroboration counts distinct scanner *names*, which overstates independence:
Grype and Trivy read overlapping advisory feeds, so their agreement is closer to
one database consulted twice than to two confirmations. The one-step cap bounds
the error. Correcting it properly means adapters declaring an evidence family
(§7: "add a capability flag on the adapter") — never a scanner conditional
inside `internal/risk/`, which §7.2 and §25.3 forbid. That is an interface
change and gets its own ADR; until then it is a documented limit.

**7. Confidence can only reduce.** Range [0.5, 1.0]. Uncertainty is not
evidence, so a low-confidence finding is discounted, but no confidence value
inflates a score above what the other factors justify.

**8. Every score carries its breakdown**, including which factors were neutral
for lack of data. A score without one is an assertion, and §12 cannot explain a
gate result from a bare number.

## Alternatives considered

**Average finding risk.** Rejected: violates §10's monotonicity requirement
directly. It is also the intuitive choice, which is why it is named here
rather than left unsaid.

**Plain saturating sum** — `total = Σ risk`. This was the first design in this
ADR, and it was rejected on its own arithmetic during review. Summation makes
volume and severity interchangeable: with the draft's weights and K, **500
informational findings scored 71.3 while the single worst finding the model can
express scored 56.7**. No choice of K fixes it, because K scales both sides;
widening the severity spread only moves the crossover. The defect is inherent to
treating a project's risk as the total of its parts, so the aggregation function
had to change rather than its constants. Max-dominance does not abolish the
crossover -- nothing short of λ = 0 does, and λ = 0 discards density -- but it
moves the informational crossover from 335 findings to roughly 44,700, which is
the difference between a scale that noise can defeat and one it cannot. `docs/architecture/risk-engine.md`
keeps the case as a worked row, and property 8 keeps it as a regression test.

**Sum with a hard cap at 100.** Monotonic and simple, but every project past
the cap looks identical, and the cap lands arbitrarily. The exponential
degrades gracefully instead — the difference between bad and catastrophic stays
visible until it genuinely stops mattering.

**Pure maximum** — score the worst finding and ignore the rest. Immune to the
volume defect and monotonic, but it makes a project with one critical
indistinguishable from a project with fifty, which discards the density signal
§10 explicitly asks for. λ is the dial between the two failure modes, set near
the max end.

**Weighted sum of factors instead of a product.** Rejected: a sum lets one high
factor compensate for a low one, so a critical severity in a throwaway sandbox
still scores highly. The product makes factors *gates*, which is the contextual
behaviour §10 is asking for.

**EPSS probability as the exploitability multiplier.** Rejected on arithmetic:
a critical at a real probability of 0.073 would score below an informational
finding. Explicitly forbidden by ADR 018 §5.

**Deriving exposure per finding rather than per project.** Correct in principle
and impossible today: it needs reachability analysis and SBOM component
storage, neither of which exists. A project-level declared value is a coarse but
honest proxy; inventing a per-finding one would be fabrication.

**Letting correlation contribute a risk number directly.** Rejected in ADR 017
and reaffirmed here. Two engines producing scores makes the formula unauditable
and the monotonicity tests meaningless.

## Consequences

**Easier.** The score is arguable: every number traces to a factor, a weight,
and a documented reason. Re-tuning is a config diff. Adding a threat signal is
a change inside `Exploitability` and nowhere else. §12's gates can explain
themselves because the breakdown is already there.

**Harder.** Two constants now carry judgement instead of one. λ has no anchor as
clean as K's — it is set by the shape it produces across the worked examples
(one medium 3.9, a hundred mediums 47.0, five hundred info 1.9), which is
defensible but not derived. Both remain untested against real projects, and both
are configuration precisely so they can be corrected by evidence rather than
argument.

**Committed to.** Risk is a pure function. No AI influences it. Adding a finding
never lowers a project's score. Severity outranks volume at any realistic
scale, with the crossover points measured and published rather than asserted.
Absence of a signal is neutral, never low. No signal is counted by more than one factor. Every score
explains itself.

**Known limits, stated rather than implied.** Reachability, whether a vulnerable
component is actually deployed, vulnerability density, and genuine scanner
independence are all things this engine does not compute, because the data does
not exist yet. `docs/architecture/risk-engine.md` lists them. A score that
silently claimed to account for them would be the more dangerous kind of wrong.
