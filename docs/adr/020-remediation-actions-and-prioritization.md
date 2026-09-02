# ADR 020: Remediation is a ranked set of actions, derived not stored

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

§11 gives the rules:

> Deterministic scanner/vendor data (fixed version, upgrade path, patch
> reference) is **authoritative**. Consolidate and deduplicate recommendations
> across scanners; prioritize by risk; always identify the affected component.
> **Never invent fixes.** Track remediation status through the finding lifecycle.

Four decisions sit underneath that, and the first one is not a design choice at
all — it is a defect.

**SecureOps does not currently capture the fix data it calls authoritative.**
Grype reports `fix.versions` and `fix.state` on every match, and the parser
discards both. The single most actionable fact the platform can obtain — "this
is fixed in 0.52.0" — has been on disk in the fixtures since Phase 3b and has
never reached the canonical model. Nothing can be built on top of §11's
authoritative data until it exists.

**What the unit of remediation is.** A finding is not a unit of work. One
`npm upgrade` can close five findings reported by two scanners, and presenting
those as five tasks is the fragmentation §2 says the product exists to remove.

**What "prioritize by risk" means** once one action covers several findings.
The obvious reading — sum the members' risk — contradicts the aggregation ADR
019 settled: under max-dominant aggregation, removing the one finding setting a
project's floor can matter more than removing six mediums that sum higher.

**Where remediation state lives.** Correlation and risk are both recomputed and
persisted after each scan. Copying that pattern here has a specific cost, and
§11's lifecycle requirement is the thing it would break.

## Decision

**1. Fix facts become a canonical attribute, with a state, not a string.**

```text
Fix { State, FixedVersions, References }
State ∈ { fixed, not-fixed, wont-fix, unknown }
```

`unknown` is the zero value and means no scanner said. It is distinct from
`not-fixed` ("a fix is being worked on") and from `wont-fix` ("there will never
be one"), and the difference is the whole point: recommending an upgrade for a
`wont-fix` vulnerability sends someone to look for a version that does not
exist. This is the same discipline ADR 018 applied to EPSS — absence is not a
value — applied to the one field §11 calls authoritative.

Grype populates it from `fix.versions` / `fix.state`. Trivy and Semgrep
contribute references. Gitleaks contributes nothing, because no vendor fix data
exists for "you committed a credential", and inventing one is exactly what
§11 forbids.

**2. The unit is an action, and its kind is derived from the finding's
category, never from the scanner that reported it.**

| Category | Fix state | Action |
|---|---|---|
| dependency, container | `fixed` | upgrade the component |
| dependency, container | `wont-fix`, `not-fixed` | no fix available — mitigate or accept |
| secrets | — | revoke and rotate the credential |
| iac | — | change the configuration |
| sast | — | change the code |
| license | — | review the licence |

Deriving the kind from `Category` rather than from `Scanner` is not a stylistic
preference: §7.2 and §25.3 forbid branching on a scanner's name outside its
adapter, and a `switch scanner` here would leak the abstraction into the last
engine that had stayed clean of it.

**3. Actions are ranked by the risk they remove, not by the risk they contain.**

```text
riskRemoved(action) = score(live findings) − score(live findings − action.members)
```

The Phase 6 engine, run twice. This answers "what should I do first" rather
than "what is worst", and under max-dominant aggregation the two genuinely
differ. It is deterministic, it inherits every property ADR 019 proves, and it
costs O(actions × findings), which is bounded by the same limits correlation
already lives within.

**4. A remediation plan is derived on read, never stored.**

Correlation and risk are persisted; this is not, and the reason is §11's own
requirement to track remediation status through the finding lifecycle. A stored
action has a status of its own, which drifts from its members' the moment
someone marks one a false positive. A derived action cannot drift: its status
*is* its members' status, by construction rather than by a reconciliation job
nobody wrote.

The second reason is that a plan is advice about the present. A score is a
statement about a moment and is stored for exactly that reason (ADR 019); "what
should I do now" has no history to preserve, and a stored one would only ever
be a cache with a staleness window.

**5. Every fact carries its source, and no fact is ever invented.**

`vendor · scanner · derived`, on each statement rather than on the action.
§11 requires AI-derived content to be structurally distinguishable from
verified data, so the discriminator includes `ai_explanation` — declared,
documented as never produced, and enforced by a test. Nothing in SecureOps
generates it, because §25.15 forbids a Claude Code or MCP runtime dependency
and no model integration exists.

An action never states a version that no scanner reported. Where the members
disagree the action lists every reported fixed version rather than choosing.

## Alternatives considered

**Rank by summed member risk.** Simpler and O(findings), and wrong in exactly
the case ADR 019 exists to prevent: five mediums summing to 40 would outrank
removing the critical that is actually setting the project's floor.

**Rank by worst member severity.** Explainable and needs no risk engine, but
discards exposure, exploitability, and asset criticality — reducing
prioritization back to the severity sort §10 forbids.

**Choose a single upgrade target per component.** Rejected as fabrication.
Picking "the" version that satisfies several advisories needs ecosystem-specific
version ordering — semver, PEP 440, Maven, Debian epochs — and a comparator that
is right for one is wrong for another. A confidently wrong upgrade target is
worse than an honest list, so the action reports every fixed version its members
reported and leaves the ordering to whoever knows the ecosystem.

**Store the plan per scan, like risk.** Rejected on §11: a stored action's
status drifts from its members'. It would also add a migration, a store, and a
worker step to cache something cheap to derive.

**Group by scanner.** Would produce "Grype says upgrade express" beside "Trivy
says upgrade express" — the fragmentation the product exists to remove, and a
scanner conditional in the core besides.

## Consequences

**Easier.** One upgrade appears once, ranked by what taking it actually buys.
Adding a scanner that reports fix data adds facts to existing actions rather
than a new list. §12's gate can name the smallest set of actions that would move
a project below a threshold, because the ranking already measures that.

**Harder.** Risk-removed ranking runs the risk engine once per action, so
remediation inherits ADR 019's calibration: if the weights are wrong, the
ordering is wrong in the same direction. Actions are recomputed on every read
rather than cached, which is a real cost on a large project and the reason the
finding load is already bounded.

**Committed to.** Fix facts are captured, never inferred. `unknown` is never
read as "no fix". Action kind derives from category, never from scanner name.
Every statement carries its source. No AI produces remediation content. An
action's status is its members' status.

**Known limits.** No single upgrade target per component, for the reason above.
No transitive dependency reasoning — whether upgrading a direct dependency
resolves a transitive finding needs the SBOM component storage that does not
exist. No patch generation, and none planned: SecureOps says what to do, and
does not write the diff.
