# ADR 022: The audit log is an append-only table, written in the same
# transaction as the change it records

- **Status:** Accepted
- **Date:** 2026-09-02

## Context

§15.6 requires security-sensitive actions to be audit-logged with who, when,
what changed, and the previous and new value. §12 names policy changes
specifically. §17 requires `audit_logs` to be append-only.

Since Phase 3a, SecureOps has had audit *logging* and no audit *log*: a
middleware writes a structured line naming the principal, the method, the path,
and the status. That was honest for what existed — the mutations were creating
projects and enqueuing scans — and it was recorded as T-24, Partial.

Phase 8 changes the calculation. A policy is the control that decides whether
insecure code ships. Someone who can raise `max_critical` from 0 to 50 can turn
the gate off, and a log line saying `PUT /policy 200` does not record that they
did, what it was before, or what it became. The one action §12 singles out as
security-sensitive would be the one the system cannot reconstruct.

This ADR is why the durable table lands in Phase 8 rather than Phase 11, and
what it does and does not buy.

## Decision

**1. `audit_logs` is a table, and the write happens in the same transaction as
the change.**

An audit record written after a successful commit can be lost — the process
dies, the write fails, the connection drops — and the resulting gap is
indistinguishable from a change nobody made. Writing both in one transaction
makes the record and the change atomic: either the policy changed and the log
says so, or neither happened.

This is the property that makes the log worth having. A best-effort audit trail
is a trail with silent holes exactly where something went wrong.

It is enforced by the type system rather than by a comment: `audit.Write` takes
a `pgx.Tx`, so passing a connection pool is a compile error. The rule was
briefly a convention instead, and the difference matters because the failure it
guards against only becomes observable when a commit fails — which is precisely
when nobody is watching, and which no reasonable test can force.

**2. Append-only, enforced by the database rather than by convention.**

A trigger on the table raises on any `UPDATE` or `DELETE`. Convention is not a
control: §15.13 forbids security through obscurity, and "we only ever insert" is
a statement about the code written so far, not about the code somebody writes
next.

The trigger is the portable half. A deployment should **also** revoke `UPDATE`
and `DELETE` from the application role, which the migration cannot do because it
does not know that role's name — a superuser can still drop the trigger, so this
bounds accident and ordinary compromise rather than a fully privileged
attacker. That limit is restated under Known limits rather than left implied.

**3. Before and after are stored as JSON, not as prose.**

§15.6 asks for the previous and new value. A rendered sentence answers "what
happened" and not "what exactly changed", and the second is the question an
investigation asks. JSON keeps the diff machine-comparable and survives the
model gaining fields.

Values are redacted through the same rules the rest of the system uses: an audit
record must never become the place a secret is finally written down (§15.3).

**4. It records the actor SecureOps actually has, and says so.**

The interim bearer token labels a client, not a person (ADR 006). The audit
record stores that label and marks it as a token label rather than a user
identity. Recording it as a user would be a more useful-looking field and a
false one — the log would claim an attribution the authentication model cannot
support.

**5. Authorization is still absent, and this does not fix it.**

T-23 remains open. Every valid token can change every project's policy, and the
audit log records *who did it*, not *whether they were allowed to*. Detection is
not prevention. This is a deliberate, recorded deviation: §12 asks for both, and
Phase 8 delivers one.

The reason to ship it anyway is that the alternative is worse in both
directions — no audit and no authorization — and the audit log is the control
that makes the missing one survivable, because a policy weakened by someone who
should not have is at least reconstructible.

## Alternatives considered

**Keep log-only until Phase 11.** The consistent choice, and it would mean
shipping the gate with its own §12 requirement unmet, in the phase that
introduces the thing the requirement is about. This is the same reasoning that
moved authentication into Phase 3a rather than shipping a write endpoint bare.

**Write the audit record after the change commits.** Simpler, and it loses
records precisely when something abnormal happens.

**Ship authorization too.** Correct and much larger: it needs an identity model,
roles, project scoping at the data layer, and a migration path for existing
tokens. That is Phase 11, and doing it badly under time pressure in Phase 8
would be worse than doing it deliberately later.

**Log to an append-only file or an external service.** Rejected for now: it adds
an operational dependency and a second consistency problem, and it cannot
participate in the transaction that makes decision 1 work.

## Consequences

**Easier.** Policy changes are reconstructible: who, when, from what, to what.
Phase 11 inherits a table rather than a greenfield requirement, and the finding
lifecycle transitions that §17 requires have somewhere to record who and why
when they land.

**Harder.** Every audited mutation now needs a transaction and a payload, so a
handler cannot casually write and return. That friction is the point.

**Committed to.** The record and the change are atomic. The table is
append-only at the database level. Before and after are captured. Secrets are
never written into an audit record. The actor is described as what it is.

**Known limits, stated rather than implied.** No authorization (T-23), so the
log records unauthorized changes as faithfully as authorized ones. No retention
or rotation policy yet, so the table grows without bound. No tamper-evidence
beyond append-only permissions — a database superuser can still rewrite history,
which is what §14.7's least-privilege rule for workers exists to bound and what
T-18 tracks for services.
