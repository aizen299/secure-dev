# ADR 028: An audit reference is history, not a live relation

- **Status:** Accepted
- **Date:** 2026-09-03

## Context

A project created through the API cannot be deleted. Attempting it fails with:

```text
ERROR: audit_logs is append-only: UPDATE is not permitted
CONTEXT: SQL statement "UPDATE ONLY audit_logs SET project_id = NULL WHERE ..."
```

Two controls introduced in the same migration contradict each other.
`0011_audit_logs.up.sql` line 30 declares
`project_id uuid REFERENCES projects (id) ON DELETE SET NULL`, and lines 64-70
install triggers that refuse **every** `UPDATE` and `DELETE` on the table. The
cascade the foreign key requires is precisely the statement the trigger forbids,
so the delete can never succeed once a single audit row references the project.

Nothing caught it because nothing tried. Every test that deletes a project uses
one created directly in the fixture, without the audit record the API writes.

The blast radius is not test data. Since ADR 022, creating a project through
the API writes an audit record, so **every project a real deployment has ever
created is permanently undeletable** — and the error names neither the project
nor the actual cause. In this repository's own development database it
accounted for 100 of 134 undeletable test projects.

### What the table already says

`audit_logs` has two columns that identify what a record is about:

```sql
resource_id   text,                                        -- no constraint
project_id    uuid REFERENCES projects (id) ON DELETE SET NULL,
```

`resource_id` holds the id of a finding, a scan, or a policy, with no foreign
key. A deleted finding's id dangles there and nothing breaks, because the
column records *what this entry was about* rather than *what currently exists*.
`project_id` was given a constraint that its neighbour never had. The
inconsistency is the bug.

## Decision

### 1. `audit_logs.project_id` loses its foreign key

It becomes a plain `uuid` — the same contract `resource_id` has always had.

An audit log is a historical record. It answers "what happened, to what, by
whom, when", and every one of those facts stays true after the subject is
deleted. A foreign key asserts something different and stronger: that the thing
referred to still exists. That is a claim about present state, and an audit
table is the one place in a schema that is explicitly not about present state.

The append-only trigger is untouched. No exception is carved into it, and no
audit row is ever mutated.

### 2. The project's slug is recorded on the entry

`audit_logs.project_slug` is written at insert time, resolved inside the
transaction that is already open.

Dropping the foreign key means an id can outlive its project, and an id alone
degrades badly: six months later `project 38150c6b-b3c0-…` is a record that
proves something happened and tells an investigator nothing about what. With
the slug, the same record still reads `policy changed on checkout-edge`.

Resolved in `audit.Write` rather than passed by callers. Three of the four call
sites hold only a project id, so requiring the slug as a parameter would mean
three lookups written three times, each able to drift or be forgotten. One
lookup in the writer is correct everywhere by construction, and it runs in the
caller's transaction — so a project created and audited in one transaction
resolves its own slug, and a project deleted concurrently cannot resolve to a
stale name.

The cost is one `SELECT` per audit write. Audit writes happen on human and API
actions, never in a scanning hot path.

## Alternatives considered

**Soft-delete projects — add `deleted_at`, never hard-delete.** Closest to
§17's literal wording, and it was the option this decision most nearly took.
Rejected on the shape of the resulting defect: every read across projects,
scans, findings, risk, policies, and remediation would have to filter
`deleted_at IS NULL`, and the failure mode of forgetting one is a deleted
project silently reappearing in a security view. It also leaves the
contradiction in place rather than resolving it — the first genuine hard delete
would fail exactly as it does today. Soft deletion remains available later as a
product feature; it is not a fix for this.

**Exempt the cascade's update from the trigger.** Makes the delete work by
allowing an `UPDATE` that only nulls `project_id`. Rejected twice over. It
mutates an audit record, which is the single thing append-only forbids, and an
exception in that guarantee is a thing an attacker reads carefully. And nulling
the column *destroys* the fact that the entry concerned that project — it
weakens the audit trail in order to permit a deletion, which is the wrong
direction of trade for this table.

**Leave it, and document that projects are undeletable.** Honest, and it makes
a schema contradiction into a product rule. The rule nobody chose would then be
enforced by an error message about a table the operator did not touch.

## Consequences

**What becomes possible.** Projects can be deleted. Their audit history
survives the deletion intact and remains readable, which is stronger than what
the original design intended — `ON DELETE SET NULL` would have erased the
project reference from every historical record.

**What we accept.** `project_id` can name a project that no longer exists.
That is correct for a historical record and is already true of `resource_id`.
Anything joining `audit_logs` to `projects` must use an outer join and expect
misses.

**What is unchanged.** The append-only guarantee, with no exceptions. The
trigger still refuses every `UPDATE` and `DELETE`, and the recommendation to
revoke those privileges from the application role at deployment time still
stands.

**What this does not do.** Deleting a project still cascades to its findings,
scans, issues, risk scores, and policies, and those are gone. This decision is
about the audit trail surviving, not about the security data doing so. A
deployment that needs recoverable projects wants soft deletion as a feature,
argued on its own terms.
