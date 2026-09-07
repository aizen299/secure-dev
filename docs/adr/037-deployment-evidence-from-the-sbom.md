# ADR 037: The SBOM says whether a package is deployed, and does not move the score

- **Status:** Accepted
- **Date:** 2026-09-07
- **Amends:** [ADR 017](017-correlation-issues-and-severity.md)

## Context

10a made a scan's bill of materials queryable. 10b was scoped as "correlation
uses it", to answer the question the roadmap calls the largest available gain:
*is this vulnerable package actually present in the built artifact, or merely
declared?*

Investigating what that costs and buys changed the shape of the change, and this
ADR records the changed shape rather than the assumed one.

**The obvious reading does not work.** "Escalate a finding whose package appears
in the SBOM" sounds right and is nearly vacuous. Grype reads the same lock file
syft does, so a dependency finding's package is almost always in the repository
SBOM by construction. And when an image is scanned, Trivy already produces a
finding for a vulnerable installed package, which `purl` already joins to the
repository finding, which already escalates (ADR 025). Presence adds a fact the
engine mostly already has.

**The discriminating signal is absence.** A finding whose package is *not* in
the built artifact's inventory is a finding about something nobody deployed — a
dev dependency, a package pruned at build, an example directory. That is the
false positive the exposure factor cannot currently see, because exposure is a
property of the project and applies to every finding in it equally.

Absence is also where the danger is. Acting on it means **lowering** the
apparent seriousness of a real vulnerability on the strength of an inventory
being complete.

## Decision

**Deployment evidence is recorded on an issue and does not change any severity
or score.**

### 1. What is computed

For a project with both a repository scan and an image scan, each issue keyed by
`purl` gains one of three states:

```text
deployed      the package is in the most recent image scan's inventory
not_deployed  it is not, and that inventory was complete
unknown       there is no image scan, or its inventory was truncated
```

`unknown` is a first-class value and the default, not a gap to be filled later.
Most projects have no image scan, and a state that quietly meant "probably fine"
would be the same failure as an EPSS score defaulting to zero (ADR 018).

### 2. It does not move a severity, in either direction

Correlation may already raise a finding's severity through
`Subject.IssueSeverity`, and the risk engine takes that value only when it is
worse than the finding's own — "correlation may raise a finding's severity,
never lower it". This ADR does not change that, and deliberately does not use it.

**Escalating on `deployed` would be noise.** The cross-domain escalation that
matters already fires: a Grype repository finding and a Trivy image finding on
one `purl` is two categories in one issue, and ADR 017 escalates it. Adding a
second reason for the same escalation changes no outcome.

**De-escalating on `not_deployed` is the one worth wanting, and is refused
here.** It means quietly reducing a real vulnerability's contribution to a score
because an inventory did not mention its package. Every way that inventory can
be wrong then becomes a way to under-report: a cataloguer syft does not have for
some ecosystem, a package installed by a build step rather than a manifest, a
multi-stage image whose final layer we scanned and whose build layer we did not.
The engine cannot distinguish "not in the artifact" from "not in the artifact we
looked at", and §8's rule against inventing relationships applies equally to
inventing their absence.

The tool that already exists for this is the one that keeps a human in the loop.
A person who can see "declared in `/examples/go.mod`, not present in the
deployed image" can dismiss the finding as a known risk — audited, attributed
and reversible (ADR 024). That is a better answer than a number that moved for
reasons nobody reviewed.

### 3. What it changes for a reader

The evidence appears on the issue and in the API, as prose alongside the
existing linking evidence, in the vocabulary correlation already uses. An issue
that is `not_deployed` says so, names the image scan it was compared against,
and says when that scan ran.

That is the whole change. It makes a fact visible that no query could previously
answer, and leaves the judgement where §11 and ADR 024 already put it.

### 4. What would have to be true to act on it

Recorded so that a later decision to de-escalate is an argument rather than a
rediscovery. All of these, not any:

- The image scan is `completed`, not `partial`.
- Its inventory carries no truncation degradation.
- The image and the repository were scanned at compatible commits — which
  nothing currently records, and is the hardest of the four.
- Enough real projects have been observed for the `not_deployed` rate to be
  known rather than assumed.

The fourth is the honest blocker. Nobody has yet seen this run on a corpus, and
a factor that changes scores should not be introduced on reasoning alone —
§10 requires every factor's derivation to be documented, and "we expect this to
be right" is not a derivation.

## Alternatives considered

**A new correlation key, `sbom:` or `deployed:`.** Rejected by the test ADR 026
and ADR 025 already applied to `endpoint:` and `image:`: does the key let the
engine assert something it could not otherwise assert? It does not. Deployment
is an attribute of one issue, not a thing two findings share, and every finding
in an artifact would share the key — making the bucket the whole scan, which is
a filter rather than a relationship.

**A new risk factor, `Deployment`.** The shape 10b was originally imagined as.
Rejected for now under §24 and §10: it changes the formula, requires a weight
nobody can derive from evidence yet, and its useful direction is downward. If it
is ever added, it will be its own ADR with the four conditions above satisfied.

**De-escalating severity rather than the score.** Same objection arriving one
layer earlier, and worse: severity is what a human reads first, so lowering it
hides the finding rather than contextualising it.

**Doing nothing until an image scan exists for most projects.** Considered
seriously. Rejected because the evidence is useful to a person immediately, at
no risk, and because building the plumbing now means the corpus that would
justify §4's conditions starts accumulating.

## Consequences

**What becomes possible.** The question "is this actually deployed?" gets an
answer for the first time, per finding rather than per project. A person
triaging can see that a critical CVE is in an example directory that ships
nowhere, and dismiss it with that reason recorded.

**What does not change.** No risk score moves. No severity moves. The README's
"exposure is per project, not per finding" limitation stands, narrowed: the
*evidence* is now per finding, and only the *scoring* remains per project.

**What this admits.** 10b delivers less than it was scoped as. The reason is
that the valuable half — acting on absence — turned out to be the dangerous
half, and the safe half was mostly redundant with escalation that already
happens. Recording that is more useful than shipping a factor whose weight
nobody could defend.

**A cost.** Correlation gains a dependency on the component store, so a pure
engine now takes one more input. It stays pure — the store is read before the
engine runs and passed in, as findings already are — but the wiring is larger
and the worker must load an inventory it previously did not.
