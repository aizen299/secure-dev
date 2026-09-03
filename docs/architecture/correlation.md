# Correlation

Correlation answers one question: **do several of these findings describe the
same underlying problem?**

It is the second half of the claim in CLAUDE.md §2 — that SecureOps turns
fragmented scanner output into one contextual security decision. Normalization
makes five scanners speak one language. Correlation is where the platform starts
saying things no individual scanner said.

The design decision and its rationale are in
[ADR 017](../adr/017-correlation-issues-and-severity.md). This document is the
rule set: what is compared, what is asserted, and what is deliberately not.

## Position in the pipeline

```text
Raw → Normalization → Deduplication → CORRELATION → Risk → Remediation → Policy
```

Correlation consumes canonical findings and nothing else. It never sees raw
scanner output (§9), never performs I/O, and never branches on a scanner's name
(§7). Given the same findings it produces the same issues, always — the same
purity contract normalization holds, and for the same reason: it is the only way
to test the engine against fixtures rather than against a live scanner.

**Its input is the project's live findings, not one scan's.** A Grype finding
recorded on Monday and a Semgrep finding recorded on Tuesday describe one
problem or they do not; which scan produced them is irrelevant. Scan-scoped
correlation would miss every pairing that spans scans, which for an
incrementally scanned project is most of them.

Live means these statuses: `open`, `reopened`, `acknowledged`, `in_progress`.
Excluded: `resolved`, `false_positive`, `ignored` — correlating a dismissed
finding into a live issue would resurrect a decision somebody already made.

## Correlation keys

Findings are bucketed by key and compared only within a bucket. This is not an
optimization detail; it is what makes the engine's assertions enumerable. Every
relationship SecureOps claims traces to exactly one shared attribute, and that
attribute is what gets shown to the person reading it.

| Key | Derived from | What it means |
|---|---|---|
| `cve:<id>` | `Finding.CVE` | the same named vulnerability |
| `purl:<purl>` | `Finding.PURL` | the same component at the same version |
| `file:<path>` | the occurrence's normalized path | the same file |

Findings with an empty value for a key simply do not enter that bucket. A
finding usually enters more than one — a Grype result has both a CVE and a PURL
— and that is intended: it participates in the "this vulnerability" grouping and
the "this component" grouping, which are different questions.

### Future keys

None are pending. Both keys that were named as future work have now been
decided against, on the same test.

### The keys that were expected and are not being added

`image:` and `endpoint:` were both named here as future work, blocked on
scanners. Both scanners have landed and neither key was added — ADR 025 and
ADR 026 respectively — and the reasoning generalises, which is why it is kept.

The test is: **does this key let the engine assert something true it could not
otherwise assert?**

For `endpoint:`, the answer today is no. Only ZAP produces endpoint locations,
so every member of the bucket has category `dast` — and `formIssue` requires two
distinct categories, while the co-location rule below returns nothing when
categories match. The key would form no issues and emit no links. It becomes
justified when a second source of endpoint data exists: an OpenAPI import, or a
SAST rule that knows which handler serves a route.

For `image:`, the answer is no for a different and stronger reason.

Correlation asserts relationships. "These findings are in the same image" is not
a relationship — it is a filter, and the difference shows up in what the engine
would actually emit:

- Every finding from one image carries the key, so the bucket is the entire
  scan rather than a subset of it.
- `linkBucket` is pairwise, so a bucket at `DefaultMaxBucketSize` produces
  124,750 links, each carrying the single fact that the finding's `image` column
  already carries.
- No issue would form from any of them. Every member has one category, and
  `formIssue` requires two.

The work of crossing the repository/image boundary is already done by `cve:` and
`purl:`, which is measurable rather than hoped for: grype over a repository and
trivy over an image both emit `pkg:npm/express@4.17.1` byte for byte. "Show me
everything wrong with this image" is a query on an indexed column, and that is
where it belongs.

### The bucket cap

A bucket holding more than **500** findings is sorted by fingerprint, truncated,
and the truncation is *reported* — the same discipline as
[ADR 010](../adr/010-scanner-degradation-reasons.md): a limit being reached is a
visible, structured outcome, never a silent one. Comparison within a bucket is
pairwise, so an uncapped bucket in a monorepo is a hang in the scan-completion
path.

Truncation is deterministic, so the same findings produce the same truncated
result rather than an arbitrary one that changes between runs.

## Relationships

The vocabulary is §8's, and only the first merges — which normalization does,
before correlation ever runs:

| Relationship | Test | Confidence | Effect |
|---|---|---|---|
| **exact duplicate** | identical fingerprint | — | merged by normalization; never reaches correlation |
| **likely duplicate** | same `purl` + same category, neither carrying a CVE | medium | linked |
| **related** (CVE) | same `cve` | high | linked |
| **related** (component) | same `purl` | medium | linked |
| **related** (file) | same file, **different** categories | low | linked |

The file rule requires differing categories on purpose. Two Semgrep findings in
one file are two findings in one file — asserting a relationship between them
adds nothing a path sort would not show. A hardcoded credential *and* an
injection flaw in one file is a different statement, and it is the cheapest
cross-domain signal available before image and endpoint data exist.

Its confidence is `low` because co-location is the weakest evidence in the
table. §9 is explicit that weak evidence produces a `related` link with a
confidence value, never a merge.

## Issues

An issue is a set of findings that share one key. It is keyed by that shared
attribute, not by a connected component of the link graph.

**Transitive closure is deliberately not used.** If A relates to B by CVE and B
relates to C by file, connected components would place A and C in one issue —
asserting a relationship no rule ever evaluated and no evidence supports. That
is precisely the invention §9 forbids. An issue's identity is a fact ("these all
concern CVE-2026-1234"), so it is explainable in one sentence and cannot chain.

A finding may belong to several issues. That is not a modelling failure; it is
the honest answer when a finding is both an instance of a vulnerability and an
instance of a component's problems.

### When an issue forms

| Key | Forms an issue when |
|---|---|
| `cve:` | ≥ 2 members |
| `purl:` | ≥ 2 members |
| `file:` | ≥ 2 members spanning ≥ 2 distinct categories |

A single-member issue is never created. Wrapping every lone finding in an issue
would make the issue count and the finding count the same number, and an entity
that adds no information is worse than no entity — it costs a table, a join, and
a concept to learn.

The `file:` restriction is the same cross-domain requirement as the file link
rule: a file with many findings of one kind is a busy file, not a contextual
issue.

### Membership evidence

Every membership records why that finding is in that issue, in a sentence a
person can read: `same vulnerability CVE-2026-1234`, `same component
pkg:npm/express@4.17.1`, `same file server.ts, categories sast and secrets`.

§9 requires correlation to be explainable. A membership with no stated reason is
an assertion, and SecureOps does not make assertions it cannot show the working
for.

## Issue severity

An issue's severity starts at the **highest severity among its members** and
rises by **at most one step** when its members span **two or more distinct
categories**.

```text
info → low → medium → high → critical
```

`unknown` is not on that ladder and never escalates. Escalating "the scanner
did not say" to `low` would manufacture an assessment nobody made — the same
reason `MapSeverity` refuses to guess.

Three properties this rule is built to hold:

- **Members are never mutated.** The escalation lives on the issue. Every
  member keeps the severity its scanner assigned, so the escalation is visibly
  a derived claim rather than an edit to the evidence.
- **One step, and only across domains.** Two scanners agreeing on a CVE is
  usually one vulnerability database being consulted twice, not two independent
  confirmations. Corroboration *across* domains — a vulnerable dependency that
  code demonstrably misuses — is the contextual signal §9 is about. Unbounded
  escalation would make every much-reported medium a critical, and a scale on
  which everything is critical carries no information.
- **Severity is not risk.** Correlation emits a value on the severity enum.
  It does not produce a number, does not weigh exposure or asset criticality,
  and does not contribute to the 0–100 project score. That is Phase 6's single
  pure function (§10), and it consumes issues as an input. Two engines producing
  scores would make the formula unauditable.

## What correlation does not do

- **It does not merge.** Merging happens in normalization, only on identical
  fingerprints. §9 requires a correlated group to keep its members individually
  queryable, and §11 treats each scanner's own remediation as authoritative —
  both are lost in a merge.
- **It does not use titles, descriptions, or string similarity.** §25.5.
  Every rule above is an equality test on a structured field.
- **It does not branch on scanner names.** §7. Rules are expressed over
  categories and fields; adding a scanner adds no case here.
- **It does not invent relationships.** Where evidence is weak the output is a
  `related` link with a low confidence, which a reader can discount. Where there
  is no evidence there is no link.

## Honest limits

The §9 worked example — a Grype CVE on `express`, a Semgrep finding in
`server.ts`, and a Trivy finding of the same package in a production image
becoming one escalated issue — is **two thirds reachable**, and it is worth
being exact about which third is missing rather than implying otherwise:

- The Trivy leg now works. Image targets landed with ADR 025, and
  `TestRepositoryAndImageFindingsCorrelate` demonstrates it against captured
  output from both scanners: a dependency finding and a container finding on
  one PURL form one issue, escalated one step for spanning two domains.
- The Semgrep leg is the harder gap, and it remains open.

DAST adds a fourth domain rather than completing that example: a ZAP finding is
about a URL path, and nothing else in the model produces one. It correlates with
nothing today, which is exactly why `endpoint:` is not a key yet. A SAST finding carries a file, not a
  package. Joining it to `express` requires knowing that `server.ts` imports and
  uses `express`, which is reachability analysis — neither scanner provides it
  and correlation will not guess it. The two legs meet today only when a
  dependency finding also names the same file.

What ships correlates SAST, secrets, dependency, and IaC findings on CVE,
component, and file. That is four of the seven domains §9 eventually wants, and
the two missing keys are blocked on scanners, not on this design.

## Recomputation

Correlation is recomputed from the project's live findings after each scan, and
the previous issues for that project are replaced.

Incremental patching was rejected: an issue whose members have since been
resolved, dismissed, or re-fingerprinted must not linger, and the number of ways
a stale issue can survive an incremental update is larger than the cost of
recomputing. Recomputation is a pure function of the current findings, which
also means an issue set can always be regenerated and never has to be trusted as
irreproducible state.

## Determinism

Same findings in, same issues out — asserted by unit tests, not assumed:

1. Findings are processed in fingerprint order, so input order cannot affect
   output.
2. Bucket truncation picks by fingerprint order, so a capped bucket is capped
   identically every time.
3. Issue keys are derived from field values, never from iteration order or
   generated identifiers.
4. Links and members are emitted sorted.
