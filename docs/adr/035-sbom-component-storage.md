# ADR 035: SBOM components are stored per scan, not as findings

- **Status:** Proposed
- **Date:** 2026-09-05

## Context

Syft has produced a CycloneDX SBOM for every repository and image scan since
Phase 3b. Nothing reads it. The bytes are persisted as a raw result and no code
has ever parsed them into anything queryable, which CLAUDE.md §1 records as a
known gap and §5 anticipates with a package — `internal/sbom/` — that does not
exist.

The normalization model already refuses to make components into findings, and
gives the reason: an SBOM is an inventory and nothing in it is *wrong*, so
forcing components into `Finding` would mean every consumer filtering them back
out. Syft is deliberately the one adapter that does not implement `Normalizer`.
That reasoning stands. What is missing is the other half — a model components
*do* belong in.

The cost of not having one is specific rather than general. Grype reports a CVE
against `express@4.17.1` because a lock file declares it. Whether that package
is in the artifact anybody deployed is a different question, and SecureOps
cannot ask it: exposure is a property of the project, applied to every finding
in it (T-38, and the "Exposure is per project, not per finding" limitation in
the README). A declared-but-unbundled dependency scores exactly like a deployed
one.

## Decision

**Components are a first-class model with their own table, captured per scan.**

### 1. Per scan, not a lifecycle entity

A component row belongs to one scan and is never updated. `findings` carry
`first_seen`, `last_seen` and a status because a finding is a problem that
persists across scans and whose lifecycle is the point (ADR 016, ADR 024). A
component is not a problem. It is a fact about one build: *at this scan, this
project contained this version of this package*.

Modelling it with a lifecycle would invent a state machine for something that
has no states. "When did this dependency arrive?" is answerable by comparing
snapshots, which is what a bill of materials is for; "is this dependency
resolved?" is not a question about a component at all.

The cost is duplication: a project scanned fifty times stores fifty copies of a
dependency that never changed. That is accepted deliberately. The alternative —
deduplicating components across scans and pointing scans at shared rows — makes
every scan's SBOM depend on rows another scan may have written, and an inventory
that is not reproducible from one scan's own output is not an inventory.

### 2. What a component carries

From the CycloneDX document syft already produces:

```text
scan_id · project_id · purl · name · version · type · cpe · location · scanner
```

`purl` is the identity that matters — it is what Grype and Trivy both emit, byte
for byte, and it is already the correlation key that joins a dependency finding
to a container finding (ADR 025). A component without a purl is stored with the
field empty rather than dropped: syft emits one for everything it recognises,
and a component it could not name is still evidence of something present.

`location` is the path syft found the component at, relative to the scan root —
`/requirements.txt`, `/go.mod`. It answers "which manifest declared this",
which is the first question anybody asks about an unexpected dependency. It is
already free of workspace paths: syft emits it relative to the scan source, and
the adapter's existing `assertNoWorkspacePaths` check fails the scan if an
absolute workspace path ever appears (ADR 008).

### 3. There is no dependency graph, and this ADR does not invent one

Syft's `cyclonedx-json` output contains no `dependencies` array. Verified
against real output and against a fresh syft run: the key is absent, not empty.

This bounds what the change buys, and the bound is worth stating because the
opposite was assumed when the work was proposed. **Transitive reasoning stays
out of reach.** "If I upgrade this package, does it fix the CVE two levels
down?" is not answerable from a flat inventory, and the remediation engine's
"speaks only about the package it names" limitation is unchanged by this ADR.

Syft's native `syft-json` format *does* carry `artifactRelationships`. Capturing
it would mean either a second scanner invocation or replacing CycloneDX, which
is a standard chosen deliberately and consumed by tools other than this one.
Both are real options and neither is this change.

### 4. Bounded, like every other parse

An image SBOM can carry thousands of components. `MaxComponents` caps what one
scan stores, and exceeding it is a **degradation** recorded against the scan
(ADR 010) rather than a silent truncation or a failed scan. A partial inventory
that says it is partial is usable; one that does not is a lie about what a
project contains, which is the same failure mode the stale-vulnerability-db
guard exists to prevent.

### 5. Parsing is pure

`internal/sbom` takes bytes and returns components, with no I/O, exactly as
normalization does (§8). The existing fixtures — empty, malformed, truncated,
wrong-format, no-components, and the workspace-path leak — are the cases it must
handle, and they already exist because Phase 3b wrote them.

The parser lives in `internal/sbom` rather than in the syft adapter because
CycloneDX is a format, not a scanner: trivy can emit it too, and a parser behind
the adapter boundary would have to be duplicated or reached across it (§7 rule
3). What stays in the adapter is the decision to *ask* syft for CycloneDX.

### 6. What this change deliberately does not do

- **It does not touch correlation.** Joining "this finding names a package" to
  "this scan's SBOM contains it" is a change to correlation semantics, which is
  material under §24 and needs its own ADR amending ADR 017. That is the next
  change, not this one.
- **It does not touch the risk formula.** When correlation does use components,
  the deployed fact will reach the score through the escalation path ADR 017
  already defines and ADR 019 already consumes — `Subject.IssueSeverity` — not
  as a new multiplier. The formula stays as ADR 019 derived it.
- **It adds no scanner and no dependency.**

## Alternatives considered

**Components as findings with a benign severity.** Rejected for the reason
already recorded in `validCategory`: nothing in an inventory is wrong, and every
consumer would filter them out. It would also corrupt the numbers the product
leads with — a project's finding count would become its dependency count.

**A shared component table with scans referencing it.** Saves storage and makes
"which projects use log4j" a single query. Rejected for now: it makes one scan's
inventory depend on rows another scan wrote, and reproducing what a scan saw
becomes a join against mutable shared state. The query it enables is worth
having and can be built as a view over per-scan rows later, without changing
what a scan recorded.

**Switching syft to `syft-json` for the dependency graph.** The graph is real
value and this is how to get it. Rejected as part of *this* change because it
replaces a standard format with a vendor one, and because a change that both
introduces a model and changes the format it is parsed from cannot be reviewed
as one thing.

**Storing only components that a finding already references.** Would make the
table small and the "is it deployed?" question answerable. Rejected: it inverts
the point. An inventory exists to answer questions nobody asked yet, and one
filtered to what is already known to be vulnerable cannot answer "what else is
in here".

## Consequences

**What becomes possible.** A project's inventory is queryable for the first
time: what is in it, at what version, declared where. It is the precondition for
the correlation change that follows, and for license visibility, which §6 lists
as a domain with no implementation behind it.

**What becomes harder.** Every scan now writes a second body of rows, and the
per-scan model means that body is duplicated across scans of an unchanged
project. Component counts will dwarf finding counts — the 52-component scan that
motivated this ADR produced far fewer findings — so any query that joins them
needs an index rather than a scan.

**What this does not fix.** The exposure factor stays per project until
correlation uses components. The remediation engine still speaks only about the
package it names. Nothing about a risk score changes with this ADR, and a
reader who expects it to should stop here rather than at the code.

**A migration.** One new table with a forward and a rollback, reviewed as a
security-sensitive change (§17). Nothing existing is altered.
