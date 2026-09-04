# ADR 029: The dashboard authenticates, and may then submit scans

- **Status:** Accepted
- **Date:** 2026-09-03

## Context

ADR 027 made the dashboard read-only and held a `viewer` credential, for a
reason that has not changed: an action taken through a shared, anonymous page
is attributed to the page, and an audit record naming nobody is worse than no
action at all.

Two things now push against that.

The dashboard has **no authentication at all** (T-57). Anyone who can reach it
sees every project's findings — which packages are vulnerable, where secrets
were committed, which gates are failing. Read-only bounds the damage to
knowledge rather than action, and loopback binding in compose is a deployment
convention rather than a control. It has been Open since Phase 9 shipped.

And the workflow the read-only design implies is worse in practice than it
looked on paper. Submitting a scan means a multi-line `curl` with a token
extracted from `.env`, a project id pasted by hand, and a JSON body. That is
not a security property; it is friction, and friction is what makes people
scan less.

## Decision

### 1. The dashboard authenticates before it does anything

A password, compared in constant time against `SECUREOPS_DASHBOARD_PASSWORD`,
exchanged for a signed session cookie. Every route except the login page and
the health probe requires it.

The cookie is `HttpOnly`, `SameSite=Strict`, `Secure` outside development, and
carries an expiry inside the signed payload rather than relying on the browser
to enforce one. It is signed with HMAC-SHA256; the key comes from
`SECUREOPS_DASHBOARD_SESSION_KEY` when set, and is otherwise generated per
process — which means a restart invalidates every session, and that is the
correct default for a security tool.

This closes T-57. It is not a user model: it is one shared password, so it
answers "may this browser look at this?" and not "who is looking?"

### 2. With a session, the dashboard may submit scans

It holds a `service` token — enough to create projects and scans, and
deliberately **not** `admin`, so it still cannot edit the policy that judges
them (ADR 023). Dismissing findings stays out of reach for the reason ADR 027
gives.

The exposure this creates is bounded by the login rather than by the network:
before it, anyone who reached the page could have queued arbitrary clones
against the worker.

### 3. The audit trail says "the dashboard", and this ADR does not pretend otherwise

A scan submitted through the UI is recorded against the dashboard's own
credential. The session knows a browser authenticated; it does not know who,
because there is one password.

The tempting fix — have the browser send an actor name the API records — is
refused. A client that asserts its own identity in an audit record makes that
record worthless, and worse than worthless because it looks authoritative.
Per-user attribution needs identity in the API, which is Phase 11 and T-23.

What is done instead is smaller and honest: the dashboard's token is labelled
distinctly, so an investigator reading `actor_label` can tell that an action
arrived through the UI rather than from CI.

## Alternatives considered

**Keep the dashboard read-only and ship a CLI helper.** Preserves the cleanest
version of the security story and does nothing about T-57, which is the larger
problem. A read-only page that anybody can read is still a page that leaks the
estate's weak points to anybody.

**OAuth or an identity provider.** The right long-term answer and the wrong
size for this step. It brings a provider dependency, a redirect flow, and token
refresh into a phase that needs none of them; Phase 11 can adopt it without
reworking anything decided here, because the session boundary is the same.

**Let the browser send an actor label.** Covered above: an audit record whose
subject is chosen by the client is not evidence.

**Basic auth at a reverse proxy.** Works, and puts the control outside the
application where the application cannot test it, cannot rate-limit it, and
cannot render a sensible failure. Deployments that want it can still add it.

## Consequences

**What becomes possible.** Scanning a repository is pasting a URL. The
dashboard stops being a read-only window onto work performed elsewhere.

**What becomes harder.** The dashboard now holds a credential that can write,
so compromising the page is worth more than it was. That is the trade the login
pays for, and the reason the login lands first rather than second.

**What is explicitly not solved.** Per-user identity, project scoping, and
RBAC: still T-23, still Phase 11. One password is not a user model, and this
ADR is careful not to describe it as one.
