# ADR 033: Identity, roles, and project scoping

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

[ADR 006](006-interim-bearer-token-auth.md) called bearer tokens interim and
named Phase 11 as their replacement. This is that. T-23 — the largest remaining
entry in the threat model, and one of only two still Open — says it plainly:

> Every valid token reaches every project: there is no tenancy boundary and no
> role model, so this is safe only for a single-tenant deployment.

Six other Partial entries name the same gap as the residue that keeps them
Partial: T-18, T-36, T-38, T-48, T-57, T-59. Seven threats, one change.

Two facts about the existing code shape everything below, and both were checked
rather than assumed.

**The model already expects this.** `auth.Principal` carries a comment saying
"Phase 11 widens this into a real identity; keeping it minimal now means that
widening is additive at every call site", and `audit.ActorKind` already
discriminates `token_label` from `system` so a third kind is an addition rather
than a change. The groundwork was laid; this ADR spends it.

**Scoping cannot be middleware.** Five endpoints take an opaque id and no
project:

```
GET  /api/v1/findings/{findingID}/history
POST /api/v1/findings/{findingID}/status
GET  /api/v1/scans/{scanID}
GET  /api/v1/scans/{scanID}/findings
GET  /api/v1/scans/{scanID}/gate
```

`handleGetScan` calls `s.scans.Get(ctx, id)` with no project check, because
today there is no project boundary to check against. A request handler has
nothing to compare a scope to until it has already fetched the row — which is
exactly the read that must not happen. §15.5 already says authorization is
checked "at the API boundary **and** at the data layer"; these five endpoints are
why the second half is not optional.

## Decision

### 1. Users are local accounts, not an external identity provider

A `users` table, a password verified with Argon2id, and the signed session
[ADR 029](029-dashboard-authentication.md) already established — widened from
"a browser authenticated" to "this person authenticated".

An IdP is the better long-term answer and the wrong size for this step. It
brings a provider dependency, a redirect flow, and token refresh into a phase
whose job is to close T-23, and §4 forbids adding a framework without a
documented requirement. ADR 029 already noted that "Phase 11 can adopt it
without reworking anything decided here, because the session boundary is the
same" — that remains true, and is the reason this is a deferral rather than a
dead end.

**This is the decision most worth arguing with.** If SecureOps is to be operated
by an organisation that already has SSO, doing this twice is worse than doing it
once. The argument for local accounts is that the deployment is self-hosted and
single-tenant today, and that an IdP added later replaces the credential check
without touching the roles, the scoping, or the audit attribution that are the
expensive parts of this change.

### 2. People get roles; machines get a role that no person can hold

§15.5 names four roles: Admin, Security Engineer, Developer, Viewer. Mapped onto
what the system can actually distinguish, that is three for people —

- **admin** — manages users, roles, and project membership; may edit a policy
- **engineer** — may triage findings, edit a policy, and submit scans
- **viewer** — may read

— and `service` stays as it is: a machine role, held only by a token, never
assignable to a user. A CI credential is not a junior person, and modelling it
as one would put a password field on something that has no password.

Developer and Security Engineer collapse into `engineer` deliberately. The
difference between them in §15.5 is which projects they can see, and that is
what project membership expresses; encoding it twice would let the two
disagree.

### 3. Scope is a value that reaches the query, not a check at the door

Every store method that returns project-owned rows takes a `Scope`. For
project-addressed endpoints the boundary also checks, because a 403 is a better
answer than an empty list. For the five id-addressed endpoints above, the scope
goes into the `WHERE` clause:

```sql
SELECT ... FROM scans WHERE id = $1 AND project_id = ANY($2)
```

A row outside the scope is **not found**, not forbidden. That distinction is
deliberate: `404` for a scan in another project reveals nothing, while `403`
confirms the id exists. The threat model calls this out under T-38.

`Scope` has two forms — a set of project ids, and an explicit `Global`. Global
is a value someone assigns, never the absence of a scope, so a store method
called without one is a compile error rather than a silent full-table read.

### 4. Existing tokens keep working, and stop being implicitly global

Live `service` and `admin` tokens are in CI and in the dashboard. Invalidating
them breaks a running deployment; grandfathering them as global keeps T-23 open
for whatever still holds one.

So: `SECUREOPS_API_TOKENS` gains a fourth field — `label:role:scope:secret`,
where scope is `*` or a comma-separated list of project slugs. **A token with no
scope field fails to start**, the way ADR 023's role field does, because a
default of `*` would be the permissive default this ADR exists to remove and a
default of "nothing" would break every deployment silently.

The dashboard's token gets `*` and says so out loud: it renders a fleet view, so
it genuinely needs every project. Explicit global is a different thing from
implicit global — one is a decision with a name on it, the other is an absence.

### 5. The audit trail names a person

`audit.ActorKind` gains `user`, and `Actor` gains the user id alongside the
label. Records written before this change keep `token_label` and stay truthful
about what they knew. Nothing is backfilled: an audit log that invents an
attribution it never had is worse than one that admits the limit.

This is what closes the standing caveat in ADR 022, ADR 024 and ADR 029 — that
an action taken through the UI is recorded against the dashboard's credential
rather than against whoever performed it.

### 6. A project can be archived, and cannot be deleted through the API

Archiving hides a project from lists and blocks new scans; its findings, scans
and history remain. §17 requires soft-delete for security-relevant records, and
a hard `DELETE` endpoint would be the API contradicting the project's own rule
about the records it exists to keep.

It lands here rather than earlier for the reason the earlier discussion reached:
a destructive or hiding operation needs an actor with a name, and until this ADR
there was none. Admin only, audited, reversible.

### 7. It ships in three changes, not one

The work above touches the auth model, the schema, six store packages and the
API contract. One pull request containing all of it could not be reviewed, and
"reviewed" is the only control this project has over a change to its
authorization model.

- **A — scope.** The `Scope` type, the token scope field, and enforcement at
  both the boundary and the query. No users yet. This alone converts "every
  token reaches every project" into "every token reaches the projects it was
  granted", which is most of T-23's exposure.
- **B — identity.** `users`, `project_members`, sessions, roles, and the audit
  actor. This is what lets the trail name a person.
- **C — archiving**, which needs B's actor to exist first.

Each is independently useful and independently revertible. A is the largest and
the most mechanical; B is the one with the security-sensitive cryptography in
it, and should be read with that in mind.

## Alternatives considered

**An identity provider now.** Covered in §1. The right answer for an
organisation with SSO; the wrong amount of new dependency for the phase that
closes T-23.

**Row-level security in PostgreSQL.** Enforcement in the database itself is
genuinely stronger than enforcement in Go, and it requires a database role per
user or a session variable set on every checkout from the pool. The pool is
shared across concurrent requests; getting that wrong yields cross-request
leakage that is invisible until it is a breach. Rejected as a larger risk than
the one it removes, and revisitable once the scope plumbing exists.

**Scoping as middleware only.** Cannot work: the five id-addressed endpoints
have no project until after the read. Attempting it would produce a boundary
check that looks complete and covers two thirds of the surface.

**Keeping one role vocabulary for people and machines.** Simpler to describe and
wrong in practice: it would make `service` assignable to a user and `admin`
assignable to a CI token, which is the confusion ADR 023 introduced roles to
prevent.

## Consequences

**What becomes possible.** T-23 closes. T-18, T-36, T-38, T-48, T-57 and T-59
narrow to their non-identity residue. The audit trail answers "who" for the
first time, which is the precondition for every remaining question about
accountability.

**What becomes harder.** Every store method that reads project-owned rows grows
a parameter, and every call site has to pass one. That is deliberate — a
compile error is the enforcement mechanism — but it touches `findings`, `scans`,
`issues`, `risk`, `remediation` and `policies`, and it is most of the work in
this change.

**What this phase does NOT include.** Phase 11's line in §26 also names
isolation, network restrictions, and secret handling. Those are Phase 12's
Kubernetes work (T-08, T-10, T-51) and are deliberately out of scope here;
folding them in would make one change that cannot be reviewed.

**A migration a deployment must perform.** `SECUREOPS_API_TOKENS` changes shape
and the API refuses to start on the old form. That is the third time this
variable has changed (ADR 006, ADR 023, here), and the third time the refusal is
deliberate: a token whose scope cannot be determined must not be assumed
global.
