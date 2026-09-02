# ADR 023: Interim tokens carry a role, and policy changes require admin

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

ADR 006 introduced an interim bearer-token gate: authentication with no
authorization. Every valid token reaches every endpoint on every project, which
was recorded as T-23 and left to Phase 11.

Phase 8 changed what that costs. A security policy is the control deciding
whether insecure code ships, and `PUT /projects/{id}/policy` can raise
`max_critical` from 0 to 50 and switch the gate off. The token that calls it is
the same token CI uses to submit scans — the most widely distributed credential
in the system, present in every pipeline configuration and every developer's
local `.env`.

§12 requires policy changes to be both audit-logged and authorization-checked.
ADR 022 delivered the audit half and said plainly that detection is not
prevention. This ADR is the smallest control that makes the second half true for
the endpoint that most needs it, without pretending to be the identity and
tenancy model Phase 11 owns.

## Decision

**1. A token carries a role: `label:role:secret`.**

The role lives with the credential rather than in a separate list of privileged
labels. Split across two settings, a typo in one silently grants nothing or —
worse — a renamed token quietly keeps a privilege nobody re-granted.

The format change is breaking, and deliberately so. A `label:secret` pair now
fails at startup with a message naming the new form. ADR 006 already refuses to
start with no credentials rather than defaulting to a permissive mode; silently
treating an un-roled token as admin would be that same failure in reverse.

**2. Three roles, ordered, with the minimum needed to close the stated gap.**

```text
viewer  < service < admin
```

- `viewer` reads. It performs no mutation at all.
- `service` submits scans and creates projects. This is what CI holds.
- `admin` additionally changes security-relevant configuration — today, policy.

Not §15.5's four roles (`Admin · Security Engineer · Developer · Viewer`).
Naming them that would imply a model that does not exist: these three are
route-level checks against a static token, not identities with project scoping.
Phase 11 replaces them, and calling them something different now keeps that
replacement honest rather than a silent redefinition.

**3. Enforcement is by rank at the route, and defaults to the stricter side.**

Mutating routes require at least `service`; the policy write requires `admin`.
A route with no declared requirement inherits the mutation default rather than
being open, so adding an endpoint and forgetting to protect it fails closed.

**4. This does not close T-23, and the difference matters.**

There is still no tenancy: an `admin` token can change *any* project's policy,
not merely its own. A role is not an identity, and a static token labels a
client rather than a person, so attribution remains as coarse as ADR 006 left
it.

What it does buy is blast radius. The credential distributed to every CI job can
no longer disable the gate it is being judged by, which was the specific and
realistic path from "a token leaked" to "the security control silently stopped
working".

## Alternatives considered

**A separate list of admin token labels.** Additive and non-breaking, and it
puts a credential's privilege somewhere other than the credential. Renaming a
token, or adding one, then silently carries the wrong authority.

**Keep `label:secret` and treat all tokens as admin unless configured
otherwise.** Backward compatible and permissive by default, which is the
posture ADR 006 exists to refuse.

**Use §15.5's four roles now.** Rejected as overclaiming: it would name a model
whose behaviour — project scoping, data-layer checks, real identities — is
absent, and make Phase 11 look like a refinement rather than the thing that
actually implements it.

**Full RBAC now.** Correct and phase-sized: identity, roles, project scoping
enforced at the data layer, and a migration path for existing tokens. Doing it
badly under time pressure in Phase 8 would be worse than doing it deliberately
in Phase 11.

**Leave it until Phase 11.** The consistent choice, and it would leave the
gate-disabling endpoint guarded by the most widely copied secret in the system
through the dashboard and CI phases — precisely the period when that secret gets
distributed further.

## Consequences

**Easier.** A CI token can no longer turn off the gate that judges it. A
read-only dashboard or reporting integration can hold a `viewer` token instead
of one that can create scans. Phase 11 inherits a role concept rather than
introducing one on top of unroled tokens.

**Harder.** The token format is breaking: every deployment and every `.env`
must be updated, and a stale configuration fails at startup rather than
degrading. That is the intended trade — a loud failure beats a token silently
holding more authority than its operator believes.

**Committed to.** Privilege travels with the credential. An unrecognised or
missing role is an error, never a default. Routes fail closed. The roles are
named as the interim mechanism they are.

**Known limits, stated rather than implied.** No tenancy: `admin` is global, so
one project's administrator can edit another's policy. No per-user identity, so
the audit log still records a token label. No delegation, expiry, or rotation
beyond ADR 006's overlapping-token approach. T-23 is narrowed, not closed.
