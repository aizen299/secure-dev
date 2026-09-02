# ADR 021: A gate is a set of data-driven rules, each of which explains itself

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

§12 gives the rules: `PASS` / `WARN` / `FAIL` from configurable per-project
policy, deterministic, explaining **the exact conditions** that produced the
result and never a bare verdict; policy is data rather than hardcoded
thresholds; output machine-readable for CI and human-readable for people; and a
`PARTIAL` scan must never be evaluated as though it were complete.

Four decisions sit underneath that, and one of them is a contradiction in the
specification rather than a design choice.

**The specification's own example is inverted.** §25 shows:

```text
Critical findings: maximum = 0
High findings:     maximum = 5
Secrets:           maximum = 0
Minimum risk score: 70
```

§10 defines the risk score as `0 (secure) … 100 (critical)`. Against that scale
a *minimum* risk threshold fails secure projects and passes catastrophic ones.
Every other rule in the same example is a maximum. Read as written it is not a
gate; read as a ceiling it is exactly consistent with the rest.

**Where WARN comes from.** §12 names three outcomes and the example gives one
threshold per rule. Two outcomes fall out of a threshold; the third has to come
from somewhere, and the obvious shortcut — hardcoding which rules warn and which
fail — is the "hardcoded thresholds" §12 forbids in a different costume.

**What a PARTIAL scan does to a verdict.** §13 makes `partial` a distinct state
precisely so it is never read as a clean, complete scan, and §12 says the gate
must surface degraded coverage. The failure mode is specific and severe: a
scanner that crashes reports nothing, fewer findings means fewer breaches, and
a broken scan passes a gate *because* it was broken.

**What "explains itself" means for a PASS.** A failure that lists its breaches
is obviously required. A pass that says only "PASS" is the same bare verdict
with a friendlier face — nobody can tell whether it passed because the project
is clean or because the policy checks nothing.

## Decision

**1. `max_risk_score`, not minimum.**

The rule is a ceiling: FAIL when the score exceeds it. This reinterprets §25's
example, and the reinterpretation is recorded here rather than applied quietly.
The specification wins where it and CLAUDE.md disagree, but §25 and §10 disagree
with *each other*, and only one reading is a gate at all. If the project owner
intends a "security score" where higher is better, that is a change to §10's
scale and needs its own decision.

**2. A rule is data: metric, selector, threshold, and the level it enforces at.**

```text
Rule { Kind, Selector, Max, Level }
Kind  ∈ { severity_count, category_count, risk_score }
Level ∈ { warn, fail }
```

WARN comes from the rule's own configured level rather than from a hardcoded
list of which metrics are serious. The same rule can warn on one project and
fail on another, which is what per-project policy means. The project verdict is
the worst level breached: any `fail` breach fails, otherwise any `warn` breach
warns, otherwise pass.

`Kind` plus `Selector` rather than one enum per metric, so adding a severity or
a category adds no code. The metric vocabulary is the canonical model's own —
severities and categories — never a scanner name, which §7.2 and §25.3 forbid
here as everywhere.

**3. An incomplete scan can never produce a PASS.**

Its treatment is configurable between `warn` and `fail`, and `pass` is not an
option the schema will store. The gate result carries the scan's status and the
coverage claim alongside the verdict.

This is the control Phase 6 built the `complete` flag for. Without it the gate
reads a number that got smaller because a scanner died and calls it progress.

**4. Every evaluated rule is reported, breached or not.**

The result lists each rule with its threshold, the observed value, and whether
it was breached. A PASS therefore shows what was actually checked, so "clean
project" and "empty policy" are distinguishable at a glance. §12 requires the
exact conditions; a verdict plus its supporting arithmetic is what that means.

**5. Results are persisted per scan; policies are versioned by mutation.**

`policy_results` is the record of a decision made at a moment (§17), stored for
the same reason a risk score is: a gate outcome is auditable only if it can be
reproduced. The policy in force is captured on the result, so a later edit does
not rewrite the past.

## Alternatives considered

**Hardcode which metrics warn and which fail.** Simpler, and precisely the
hardcoded thresholds §12 forbids. It also makes "max criticals = 0" mean
different things to teams that disagree about whether that should block.

**Derive WARN from proximity to a threshold** — warn at 80% of the limit.
Rejected: it invents a second threshold nobody configured, and "you are near the
limit" is a different claim from "you have broken a rule your team set".

**Let a PARTIAL scan pass when no rule is breached.** Rejected outright. It is
the one behaviour §12 and §13 both name, and it fails safe in the wrong
direction: the less a scan managed to do, the more likely it passes.

**Evaluate on stored findings rather than the scan's own result.** Rejected:
the gate answers "may this change ship", which is a question about a scan. Using
the current findings would make a gate result change after the fact, when
somebody dismissed a finding in the UI.

**Report only breached rules.** Compact and a false economy: it makes a PASS
unfalsifiable, and §12's "never a bare verdict" applies to good news too.

## Consequences

**Easier.** A team can express its own risk appetite without code changes.
CI gets a machine-readable result whose every number traces to a configured
rule. §11's remediation plan already ranks by risk removed, so "what would
un-fail this build" is answerable by walking the ranked actions.

**Harder.** Policies are now security-sensitive state that someone can weaken,
which is why §12 demands audit and authorization for changes. Audit lands with
this phase (ADR 022); authorization does not, and that gap is recorded there.

**Committed to.** Policy is data. A rule explains itself whether or not it
breached. An incomplete scan never passes. The gate never branches on a scanner
name. A stored result records the policy that produced it.

**Known limits.** No expression language: rules are threshold comparisons, not
predicates over arbitrary finding attributes. No per-branch or per-environment
policy variants. No policy inheritance across projects — every project carries
its own, and an organisation-wide default is a Phase 11 concern alongside the
tenancy model it would need.
