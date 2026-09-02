# Remediation Engine

The risk engine answers *how bad is this project*. The remediation engine
answers the only question that follows: **what should I do first?**

It is the fourth deterministic engine and the last one before the gate. This
document is the specification: the action model, where every fact comes from,
how actions are ranked, and what the engine refuses to do. The decision and its
rationale are in [ADR 020](../adr/020-remediation-actions-and-prioritization.md).

## Position in the pipeline

```text
Normalization → Deduplication → Correlation → Risk → REMEDIATION → Policy
```

Remediation consumes canonical findings — including their fix facts — plus the
project context, and produces a ranked list of actions. Like the three engines
before it, it is **pure**: same findings, same plan, always. No I/O, no clock,
no network.

Unlike correlation and risk, it is **not persisted**. A plan is advice about the
present, and §11 requires remediation status to track the finding lifecycle. A
derived action's status *is* its members' status; a stored one would drift the
moment somebody marked a member a false positive. See ADR 020 §4.

## Where the facts come from

§11 is unambiguous: deterministic scanner and vendor data is authoritative and
is the source of truth for what to do. So the first job is to actually capture
it.

| Scanner | Contributes | As |
|---|---|---|
| Grype | `fix.versions`, `fix.state` | fixed versions and fix state — the authoritative upgrade fact |
| Trivy | `Resolution`, `References`, `PrimaryURL` | prose resolution and references |
| Semgrep | `metadata.references`, rule URL | references only — Semgrep describes a class of bug, not a fix |
| Gitleaks | nothing | no vendor fix data exists for "you committed a credential" |
| Syft | nothing | produces no findings |

Gitleaks is the honest case worth stating plainly: there is no vendor fix, so
the action's guidance is SecureOps' own and is marked `derived`. It is never
dressed up as vendor data.

## The fix attribute

```text
Fix {
    State          fixed | not-fixed | wont-fix | unknown
    FixedVersions  []string
    References     []string
}
```

`unknown` is the zero value: no scanner said. It is **not** a synonym for
`not-fixed`, and neither is a synonym for `wont-fix`.

The distinction is the whole reason this is a state and not a string. A
`wont-fix` vulnerability has no version to upgrade to — ever — and telling
someone to upgrade sends them looking for something that does not exist. A
`not-fixed` one has no version *yet*. An `unknown` one means SecureOps has no
information, which is a third thing again. This is ADR 018's rule about EPSS
applied to the field §11 calls authoritative.

## The action model

An action is a distinct thing a person does. One action may resolve many
findings reported by many scanners — that consolidation is §11's requirement and
the fragmentation §2 says the product exists to remove.

**Kind is derived from the finding's category and its fix state, never from the
scanner.** §7.2 and §25.3 forbid branching on a scanner's name outside its
adapter, and this is the last engine that could have leaked it.

| Category | Fix state | Kind | Grouped by |
|---|---|---|---|
| `dependency`, `container` | `fixed` | `upgrade` | component |
| `dependency`, `container` | `wont-fix`, `not-fixed`, `unknown` | `no_fix_available` | component |
| `secrets` | — | `rotate_credential` | location |
| `iac` | — | `reconfigure` | check + file |
| `sast` | — | `change_code` | rule + file |
| `license` | — | `review_license` | component |

`no_fix_available` is a first-class action rather than an omission. "There is no
upgrade for this, mitigate or accept it" is a decision someone has to make, and
hiding those findings because they have no fix would quietly drop the ones most
likely to need a compensating control.

### Why not a single upgrade target

An action reports **every** fixed version its members reported, and does not
choose between them.

Choosing would mean ordering versions, and version ordering is
ecosystem-specific: semver, PEP 440, Maven, Debian epochs, and Go's own
pseudo-versions do not agree, and a comparator that is correct for one is wrong
for another. A confidently wrong upgrade target is worse than an honest list, so
the list is what SecureOps gives. This is a stated limitation, not an oversight.

## Ranking: risk removed, not risk contained

```text
riskRemoved(action) = score(live findings) − score(live findings − action.members)
```

The Phase 6 engine, run once over the whole project and once per action with
that action's members withheld.

**Why not sum the members' risk.** ADR 019's aggregation is max-dominant: the
worst finding sets the project's floor and everything else is pressure above it.
Summing members would rank five mediums totalling 40 above removing the single
critical that is actually holding the score up — reintroducing the exact
volume-beats-severity error the risk design exists to prevent.

Ranking by what an action *removes* also answers a different and more useful
question. The worst finding is not always the best first move: an upgrade that
clears six findings at once can beat one that clears a worse single finding, and
the arithmetic decides rather than a rule of thumb.

Ties break by member count, then by action key, so the order is total and
deterministic.

## Provenance

Every statement in an action carries its source. §11 requires AI-derived content
to be structurally distinguishable from verified data, in the model, in the API,
and in the UI.

| Source | Means |
|---|---|
| `vendor` | an advisory or vendor said it (Grype's fix versions, Trivy's resolution) |
| `scanner` | the scanner said it, without vendor backing |
| `derived` | SecureOps computed it deterministically from the above |
| `ai_explanation` | **declared, never produced** |

`ai_explanation` exists in the model so that AI content would be visible if it
were ever added, and so its absence is testable. Nothing produces it: §25.15
forbids treating Claude Code or MCP as a runtime dependency, and no model
integration exists. Deterministic rules are labelled `derived`, never "AI"
(§25.6).

## What this engine does not do

- **Never invents a fix.** An action states no version that no scanner reported.
  Where there is no vendor data, the guidance is marked `derived` and says what
  SecureOps knows, not what it guesses.
- **No transitive reasoning.** Whether upgrading a direct dependency resolves a
  finding in a transitive one needs SBOM component storage, which does not
  exist.
- **No patch generation.** SecureOps says what to do; it does not write the
  diff. Generating code changes and presenting them as verified is exactly the
  failure §11 and §25.6 prohibit.
- **No effort estimate.** Ranking measures risk removed, not how hard the work
  is. SecureOps cannot know that, and a fabricated estimate would be acted on.

## Properties the tests enforce

1. **Determinism** — same findings, same plan, same order.
2. **Consolidation** — findings sharing a component and a fix appear in exactly
   one action, with every reporting scanner retained.
3. **No invented fixes** — no action carries a version absent from its members'
   fix facts.
4. **`unknown` is not `wont-fix`** — a finding with no fix data never produces
   an upgrade action.
5. **Ranking matches risk removed** — recomputing the score without an action's
   members reproduces its rank, and removing the project's worst finding
   outranks removing several lesser ones that sum higher.
6. **Dismissed findings produce no work** — a false positive never appears in a
   plan.
7. **No scanner branching** — action kinds derive from category and fix state;
   the same finding reported by a different scanner produces the same action.
8. **Nothing is ever sourced `ai_explanation`.**
