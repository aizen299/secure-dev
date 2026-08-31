# ADR 006: Interim bearer-token authentication

- **Status:** Accepted
- **Date:** 2026-08-31

## Context

Phase 3 introduces the first write endpoints: `POST /api/v1/projects` and
`POST /api/v1/scans`. Until now the API has been three read-only health
endpoints, and `docs/security/threat-model.md` recorded T-11 (no authentication)
as open but low-exposure, with the explicit note that it "becomes urgent the
moment a write endpoint ships."

That moment is this PR.

An unauthenticated `POST /scans` is not a missing feature, it is an exposed
capability. Anyone who can reach the process could:

- enqueue unbounded scan jobs, exhausting workers and disk (a denial of service
  against the platform, using the platform's own resources);
- use the target validator as an SSRF oracle — submitting `repository_url`
  values and reading back the structured rejection reason to map which internal
  hosts resolve and which are blocked;
- read every project's scan history, which describes where an organisation's
  security coverage is weakest.

CLAUDE.md §26 assigns authentication and RBAC to Phase 11. §15.4 requires
server-side authentication on every request. Both are correct, and they collide
here: Phase 11 is where the real identity model belongs, but Phase 3 cannot ship
a public write API while waiting for it.

## Decision

**Gate every `/api/v1` endpoint except health behind a static bearer token,
verified in constant time.** Tokens are supplied through the environment as
`SECUREOPS_API_TOKENS`, a comma-separated list of `label:secret` pairs.

The label exists so that a request can be attributed. It is logged on every
mutating request and becomes the actor field when Phase 11 adds the `audit_logs`
table, so audit attribution does not have to be retrofitted onto an anonymous
call path.

Enforced at configuration load, not at request time:

- at least one token is required — the process refuses to start without one, in
  every environment, so there is no "no tokens configured means no auth" path
  that can be shipped by accident;
- each secret must be at least 32 characters, so a weak token cannot be
  configured;
- secrets are hashed with SHA-256 at load and the plaintext is not retained;
  `Config` already redacts itself for logging (§15.1–§15.3) and the token list is
  redacted the same way.

Verification compares SHA-256 digests with `crypto/subtle.ConstantTimeCompare`,
and always performs the same number of comparisons regardless of whether a
prefix matched, so response timing does not reveal how much of a token was
correct.

Health endpoints (`/healthz`, `/readyz`, `/api/v1/health`) stay unauthenticated:
they are orchestrator probe targets, and a liveness check that depends on
credentials is a liveness check that fails during a credential rotation.

## Alternatives considered

**Ship the write endpoints unauthenticated and fix it in Phase 11.** Rejected.
This is the option the threat model already argued against. It would mean
knowingly publishing the exposures listed above, and "we will secure it later"
is precisely the posture this project exists to find in other people's systems.

**Build the full Phase 11 identity model now** — users, sessions, OIDC, the four
RBAC roles, project scoping at the data layer. Rejected as scope inversion. That
model needs the entities Phases 4–8 introduce (findings, policies, remediation
actions) to know what its permissions are actually about. Designing it against
two endpoints would produce a role model built for the wrong surface, and
rewriting authorization is far more dangerous than replacing a token check.

**mTLS between clients and the API.** Rejected for now: it is a strong control,
but it moves the problem to certificate distribution for a local-development
stack and a CI client that does not exist yet. It stays on the table for Phase
12, where it fits the deployment story.

**Per-project API keys stored in PostgreSQL.** Rejected as premature. It is the
natural successor to this decision, but it requires a key lifecycle — issuance,
rotation, revocation, listing — which is real product surface, not a stopgap. A
database-backed key check also makes the auth path depend on database
availability, which is a poor trade before it buys anything.

## Consequences

What this buys: no endpoint that creates a project, creates a scan, or reads
scan history is reachable without a credential. T-11 moves from **Open** to
**Partial** — the *unauthenticated access* half is closed; the *no authorization
model* half remains open and is restated as its own threat.

What it does not buy, and must not be mistaken for:

- **No authorization.** Every valid token is equivalent and can reach every
  project. There is no tenancy boundary, so this is safe only for a
  single-tenant deployment.
- **No user identity.** A token labels a client, not a person. "Who ran this
  scan?" is answerable only to the granularity of the label.
- **No rotation mechanism.** Rotating a token means changing an environment
  variable and restarting. Overlapping tokens are supported (the list holds
  several), so a rotation need not be a hard cutover, but nothing automates it.
- **No revocation short of a restart.**

What we are committed to: Phase 11 replaces this, and the replacement must keep
the constant-time comparison and the refuse-to-start-without-credentials
behaviour. The `Principal` type is deliberately minimal (a label) so that
widening it to a real identity is an additive change at every call site.

The interim nature is recorded in three places that a reader will actually hit —
the OpenAPI security scheme description, the threat model entry for T-11, and
the README — because the failure mode for a stopgap is that it is quietly
mistaken for the finished control.
