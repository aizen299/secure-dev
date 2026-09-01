# ADR 017: Correlation produces issues, and issue severity is not a risk score

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

CLAUDE.md §9 requires an engine that decides when several findings represent one
underlying security problem. Its worked example is precise about the shape of
the answer:

> Grype CVE on `express` + Semgrep unsafe Express config in `server.ts` + Trivy
> finding the same package in a production image → **one contextual issue**
> escalated to CRITICAL, with all three sources retained as evidence.

Three things in that sentence are load-bearing, and the code as it stands
satisfies none of them.

**One issue, not three links.** `internal/normalization/dedup.go` produces
pairwise `Link` rows: A relates to B, B relates to C. Nothing says A, B, and C
are *one thing*. A pairwise graph is not an issue — it is the raw material for
one, and every consumer would have to recompute connected components for itself
to answer "how many problems does this project have?".

**Escalated.** The issue is CRITICAL while its members individually are not.
Something has to derive that, and §10 has already claimed scoring for Phase 6
and declared it a pure function producing 0–100. If correlation also produces a
number, two engines are scoring and the phases will fight.

**Correlation is a pipeline stage.** §3 lists `Deduplication` and `Cross-Domain
Correlation` as distinct stages, and §9 says correlation runs on canonical
findings. Today `linkRelated` runs inside `Deduplicate`, in a package whose
own documentation says it is pure `raw bytes → []Finding`. Linking findings by
shared CVE across scanners is not normalization; it ended up there because
dedup was the first code that had all the findings in one slice.

A fourth force is practical rather than architectural: `linkRelated` compares
every finding against every other finding. At a few hundred findings that is
invisible; at the tens of thousands a monorepo produces it is not, and it runs
inside the scan-completion path.

## Decision

**1. A correlated issue is a first-class entity.**

`correlated_issues` and `correlated_issue_members`, with the issue carrying a
deterministic key naming what its members share, and each membership carrying
its own evidence string. Findings are never destroyed or hidden by belonging to
an issue: membership is an additional fact about a finding, and every member
stays individually queryable, per §9.

An issue exists only where there is shared evidence. A finding correlated with
nothing is not wrapped in a single-member issue — that would make "how many
issues?" and "how many findings?" the same number and the entity meaningless.

**2. Correlation derives an issue severity. It does not compute risk.**

The boundary, stated so Phase 6 does not double-count:

| | Correlation (Phase 5) | Risk (Phase 6) |
|---|---|---|
| Produces | a severity on the enum | a score, 0–100 |
| Inputs | findings and their shared evidence | findings, issues, asset context |
| Question | "is this worse than its parts?" | "how much should we care?" |

Issue severity starts at the highest member severity and may rise by **at most
one step**, only when distinct scanner *categories* corroborate each other.
Corroboration across domains is evidence that a vulnerability is both present
and reachable, which is exactly the contextual signal §9 exists to surface.

Member findings are never mutated. The escalation lives on the issue, so the
original severities remain visible and the escalation stays explainable as a
derived claim rather than an edit.

**3. Correlation moves out of normalization.**

`internal/correlation/` owns every link and every issue. `normalization`
returns to merging exact duplicates and nothing else. The stage boundary in §3
becomes a package boundary.

**4. Correlation is keyed, not pairwise.**

Findings are bucketed by correlation key — CVE, PURL, normalized file path —
and compared only within a bucket. A bucket larger than a configured cap is
truncated and *reported*, following ADR 010's rule that a limit being hit is a
structured, visible outcome rather than a silent one.

**5. Correlation runs project-wide over open findings.**

Not scan-scoped. A Grype finding from Monday and a Semgrep finding from Tuesday
describe the same problem regardless of which scan produced them, and
scan-scoped correlation would miss every pairing that spans scans — which, for
a project scanned incrementally, is most of them.

## Alternatives considered

**Keep pairwise links and let consumers group them.** Rejected. Every consumer
— dashboard, risk engine, CI gate, report — would independently compute
connected components, and they would drift. It also makes the §9 answer ("one
contextual issue") a thing SecureOps never actually says.

**Merge correlated findings into one record.** Rejected outright: §9 requires a
correlated group to keep its members individually queryable, and §8 forbids
merging findings that are not identical. A merge also destroys the per-scanner
remediation, which is the part §11 treats as authoritative.

**Let correlation compute a risk contribution directly.** Rejected. §10 makes
risk a single pure function with documented weights; a second engine
contributing to the score makes the formula unauditable and the monotonicity
tests meaningless.

**Escalate by more than one step, or escalate on any shared evidence.**
Rejected. Two findings sharing a CVE is often one scanner being thorough, not
two independent confirmations. Unbounded escalation would make every
much-reported medium a critical, and a severity scale where everything is
critical carries no information. One step, and only across distinct categories.

**Leave linking in `normalization` and add grouping on top.** Tempting, because
it touches less code. Rejected because it entrenches the boundary error: the
package documented as pure `raw bytes → findings` would keep making claims
about relationships between findings from different scanners, and the next
person would reasonably add the fourth linking rule there too.

## Consequences

**Easier.** "How many problems does this project have?" becomes a query. The
dashboard, the CI gate, and Phase 6 all consume the same issue entity instead of
each deriving one. Adding a correlation rule is adding a key and a rule, in one
package, with no changes elsewhere. Normalization gets its purity claim back.

**Harder.** There is now a second thing to keep consistent as findings change:
an issue whose members are resolved must not linger. Correlation is recomputed
after each scan rather than incrementally patched, which is the simpler
correctness story and the more expensive one.

**Committed to.** Issue severity is a classification and never a score. Members
are never mutated by correlation. Every link and every membership carries
evidence a person can read — a relationship SecureOps cannot explain is a
relationship it does not assert.

**Deferred, and honestly.** The §9 example is not fully reachable today: its
third leg is a Trivy *image* finding, and image targets are not built. Nor is
DAST. The keys those need — image digest, endpoint — are named in
`docs/architecture/correlation.md` as future keys, and the engine is shaped so
each is one more key rather than a reshaping. What ships correlates SAST,
secrets, dependency, and IaC findings, which is four of the seven domains §9
eventually wants.
