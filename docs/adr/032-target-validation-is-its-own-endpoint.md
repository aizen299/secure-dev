# ADR 032: Target validation is its own endpoint

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

The dashboard's URL bar creates a project and then submits a scan against it.
When the API refuses the target — a blocked address, a bad scheme — the scan
fails and the project stays.

Measured, not theorised. Submitting `https://169.254.169.254/latest/meta-data/`
to test the SSRF guard left this behind:

```
site-169-254-169-254-latest-meta-data   0 scans
```

The refusal worked exactly as designed: `netguard` rejected the cloud metadata
endpoint and no scan ran. But the fleet list now shows a project named after a
target the platform refused, indistinguishable at a glance from a project
somebody meant to create. On a tool whose whole job is telling an operator what
is real, that is the wrong kind of wrong.

The obvious repairs are both worse:

**Roll the project back.** There is no `DELETE /projects/{id}`. Deletion works
at the database level since PR #29, and nothing exposes it over HTTP. Adding a
destructive endpoint — with the role gating and audit trail it would need — to
tidy up after a validation failure is a large amount of new surface for a small
problem, and it leaves a window where the junk exists.

**Check the URL in the dashboard first.** This is the one that looks cheapest
and is the most damaging. It means a second implementation of the address
policy in the browser tier, and the two would diverge — with the weaker one
deciding what gets created. Every previous change here has refused that, and it
would be strange to accept it now for cosmetics.

## Decision

### `POST /api/v1/targets/validate`

A read-only endpoint that runs the same `Validator` the scan handler runs, and
returns the normalised target or the reason it was refused. It creates nothing,
enqueues nothing, and writes nothing.

The dashboard calls it before creating a project. A refused target never gets
one.

The point is that this is **not** a second implementation. It is the same code
path reached earlier — the dashboard asks the API what it thinks rather than
guessing, so there is no second rule set to drift.

### It requires the `service` role, not `viewer`

Validation is read-only, which argues for `viewer`. It also **resolves a
caller-supplied hostname**, which is an outbound DNS lookup the caller chose.
That is a capability, small as it is, and `POST /scans` already gates the same
behaviour behind `service`.

Gating this at `viewer` would hand a read-only credential an outbound side
effect it does not otherwise have. Gating it at `service` grants nothing a
`service` token cannot already do by submitting a scan.

### The response says what was refused, not what exists

A rejection returns the validator's own message, which names the rule broken and
never echoes the value that broke it — the same client-safe wording the scan
handler forwards. A caller learns "cloud instance metadata endpoint", not which
addresses a host resolved to.

## Alternatives considered

**Create the project and the scan in one request.** What the dashboard actually
wants, and it duplicates two existing endpoints into a third that has to keep
their semantics in step. It also moves project creation into the scan handler,
where a partial failure gets harder to reason about rather than easier.

**Hide zero-scan projects in the fleet list.** A display fix for a data problem.
Projects with no scans are legitimate — the API lets you create one before
scanning it, and the overview reports "4 never scanned" as a real number. Hiding
them would suppress the honest ones to conceal the junk.

**Leave it.** The junk is cosmetic and the refusal works. But "the dashboard
lists targets the platform refused" is a defect a reviewer would raise, and the
fix removes a class of surprise rather than one row.

## Consequences

**What becomes possible.** A refused target costs nothing. The dashboard can
also say *why* before anything is created, which is a better failure than
"queued, then failed".

**What becomes harder.** One more round trip on every submission, and one more
public endpoint to keep in the OpenAPI spec and the contract test.

**What is explicitly not solved.** The projects already created this way stay
until somebody removes them with SQL — there is still no delete endpoint, and
this ADR does not add one. And validation remains advisory: the scan handler
still validates independently on submission, as does the worker on arrival.
Nothing here removes a check; it adds an earlier one.
