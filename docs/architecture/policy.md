# Security Policy Engine

Four engines produce a picture of a project. This one turns that picture into a
decision: **may this change ship?**

It is the last deterministic engine and the only one whose output blocks
something. This document is the specification: the rule model, how a verdict is
reached, what happens when a scan did not complete, and what the engine refuses
to do. The decisions are in [ADR 021](../adr/021-policy-evaluation-and-gates.md)
and [ADR 022](../adr/022-durable-audit-log.md).

## Position in the pipeline

```text
Normalization → Deduplication → Correlation → Risk → Remediation → POLICY
```

Policy consumes a scan's findings, its risk score, and whether the scan actually
completed. Like the four engines before it, it is **pure**: same inputs, same
verdict, always.

Unlike them, its output is a decision somebody acts on immediately — a build
that stops or proceeds. That raises the cost of every ambiguity, which is why
every rule reports itself and why an incomplete scan can never pass.

## The rule model

A rule is data (§12: "policy is data, not hardcoded thresholds"):

```text
Rule { Kind, Selector, Max, Level }

Kind     severity_count | category_count | risk_score
Selector the severity or category counted; empty for risk_score
Max      the ceiling; a rule breaches when the observed value exceeds it
Level    warn | fail
```

`Kind` plus `Selector` rather than one enum per metric, so a new severity or
category needs no code. The vocabulary is the canonical model's own — never a
scanner name (§7.2, §25.3): a policy says "no critical findings", never "no
Gitleaks findings".

§25's example policy expressed in this model:

| Rule | Kind | Selector | Max | Level |
|---|---|---|---|---|
| No critical findings | `severity_count` | `critical` | 0 | `fail` |
| At most five high | `severity_count` | `high` | 5 | `fail` |
| No exposed secrets | `category_count` | `secrets` | 0 | `fail` |
| Risk ceiling | `risk_score` | — | 70 | `fail` |

### `max_risk_score`, not minimum

§25 writes the last rule as "Minimum risk score: 70". §10 defines the risk score
as `0 (secure) … 100 (critical)`, so a *minimum* would fail secure projects and
pass catastrophic ones — it is inverted, and it is the only rule in that example
not written as a maximum.

SecureOps implements a ceiling. The reinterpretation is recorded in ADR 021
rather than applied quietly, because it is a contradiction between two parts of
the specification and the project owner may intend to resolve it the other way
by changing §10's scale.

## Reaching a verdict

Every rule is evaluated. The project verdict is the **worst level breached**:

```text
any rule breached at `fail`   → FAIL
else any breached at `warn`   → WARN
else                          → PASS
```

WARN comes from a rule's own configured level, not from a hardcoded list of
which metrics are serious. The same rule fails one team's build and warns
another's, which is what per-project policy means.

### An incomplete scan can never pass

§13 makes `partial` a distinct state so it is never read as a clean scan, and
§12 requires degraded coverage to be surfaced in the gate result.

The failure this prevents is specific: a scanner that crashes reports nothing,
fewer findings means fewer breaches, and **a broken scan passes the gate because
it was broken**. The less a scan managed to do, the more likely it would pass.

So a scan that is not `completed` produces at least WARN. The treatment is
configurable between `warn` and `fail`; `pass` is not a value the model or the
schema will accept. This is what Phase 6's `complete` flag was built for.

## Every rule reports itself

The result lists **every** evaluated rule with its threshold, the observed
value, and whether it breached — not only the breaches.

A failure that lists its breaches is obviously required. A pass that says only
`PASS` is the same bare verdict §12 forbids, wearing a friendlier face: nobody
can tell whether it passed because the project is clean or because the policy
checks nothing. Reporting satisfied rules makes an empty policy visible.

The result is emitted in two forms from one evaluation — machine-readable for
CI status checks, and a human-readable summary for a pull request comment or the
dashboard. They are renderings of the same conditions, so they cannot disagree.

## Persistence

`policy_results` stores the verdict per scan, with the policy that produced it
captured alongside. A gate outcome is a decision made at a moment; a later edit
to the policy must not rewrite what was decided.

`security_policies` holds the rules per project. Changing one is
security-sensitive: someone who raises `max_critical` from 0 to 50 turns the
gate off. Every change is recorded in the append-only `audit_logs` table, in the
same transaction as the change itself, so the record and the change are atomic
(ADR 022).

**Authorization does not exist.** Every valid token can change every project's
policy (T-23, Phase 11). The audit log records who changed what; it does not
record whether they were permitted to, because nothing decides that yet.
Detection is not prevention, and this limitation is stated here rather than
implied by its absence.

## What this engine does not do

- **No expression language.** Rules are threshold comparisons, not predicates
  over arbitrary finding attributes. "Fail if any critical is internet-facing
  and older than 30 days" is not expressible.
- **No per-branch or per-environment variants.** One policy per project.
- **No organisation-wide defaults or inheritance.** Every project carries its
  own policy; a shared default needs the tenancy model Phase 11 introduces.
- **No automatic exceptions or waivers.** A finding cannot be excluded from a
  gate for a fixed period. The lifecycle's `ignored` state is the only
  mechanism, and nothing can set it yet — see the known limitations in the
  README.
- **No CI integration.** This phase produces the result; wiring it to GitHub
  Actions, PR comments, and status checks is Phase 10.

## Properties the tests enforce

1. **Determinism** — same inputs, same verdict, same conditions, same order.
2. **Policy is data** — an empty policy passes everything; changing a threshold
   changes the verdict with no code change.
3. **Worst level wins** — one `fail` breach outranks any number of `warn`
   breaches.
4. **An incomplete scan never passes**, whatever the rules say, including when
   no rule breaches at all.
5. **Every rule is reported**, breached or not, on PASS as well as FAIL.
6. **Risk is a ceiling** — a score above `max_risk_score` breaches; a score
   below it does not.
7. **No scanner branching** — the same findings reported by different scanners
   produce the same verdict.
8. **A stored result keeps the policy that produced it**, so editing the policy
   does not change a past verdict.
