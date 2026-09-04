# ADR 031: The dashboard gets a test harness, and it is Vitest

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

`apps/web` has no automated tests. No `test` script, no runner, no test files.
That was defensible while the dashboard was a read-only window onto work
performed elsewhere: every claim it made came from the API, and the API is
tested.

It is not defensible now. Since [ADR 029](029-dashboard-authentication.md) the
tier holds security-relevant logic of its own:

- `lib/session.ts` — HMAC-SHA256 cookie signing, constant-time comparison, and
  an expiry carried *inside* the signed payload
- `lib/guard.ts` — the real server-side session check, the one the edge
  middleware deliberately does not perform
- `app/api/scans/route.ts` — a session-gated write that queues work on the
  worker
- `lib/redirect.ts` — a relative-`Location` helper that exists because the
  alternative was trusting a client-supplied `Host` header

And the recent record is not good. Three defects reached `main` in the last two
changes, each found by hand rather than by a check:

- Signing in did nothing, because a redirect resolved to the Docker container's
  own hostname.
- Selecting "Website" left the page headed `SCAN A REPOSITORY`.
- Every button written `text-[13px] … text-base` rendered at 16px, because
  `--text-base` is one of Tailwind's own font sizes and `tailwind-merge` drops
  the losing `text-*`.

The last one had been shipping silently for weeks and surfaced only because a
computed font size was measured by hand while chasing something else.

## Decision

### 1. Vitest, with jsdom and Testing Library

`vitest` for the runner, `@vitejs/plugin-react` for JSX, `jsdom` for a DOM, and
`@testing-library/react` for rendering.

Vitest rather than Jest because this app is already a Vite-shaped world in
everything but the bundler: ESM by default, TypeScript without a transform step
to configure, and the same `vite.config` conventions the ecosystem documents for
Next. Jest needs `next/jest`, a Babel or SWC transform, and CommonJS interop
decisions that are pure overhead here.

jsdom and Testing Library rather than pure-node testing, because the defects
that got through were **interaction** defects. A test of `session.ts` alone
would have caught none of the three above. The one that matters most — the
heading disagreeing with the selected mode — is only observable by rendering the
component and clicking the control.

### 2. Tested in preference order: security boundary, then contradiction

The harness is not an invitation to test everything. Three things earn a test:

1. **The session boundary.** A valid cookie validates; a tampered signature does
   not; an expiry rewritten to the far future does not. That last one is the
   property that makes carrying the expiry inside the signature worth doing, and
   it is the only place it is asserted.
2. **States that must agree.** Where one value drives several rendered fields,
   a test asserts they move together. This is the class of bug that produced
   `SCAN A REPOSITORY` under a Website selection.
3. **Refusals.** A rejected input must be rejected, and must leave nothing
   behind — which is the subject of [ADR 032](032-target-validation-endpoint.md).

Rendering assertions about spacing, colour, or animation are explicitly not
wanted. They break on every considered design change and catch nothing.

### 3. It runs where the other checks run

`make check` and CI's `web` job. A test suite that is not in the gate is
documentation.

## Alternatives considered

**Jest with `next/jest`.** The officially blessed path, and it brings a
transform pipeline and CommonJS interop this project has no other reason to
own. Vitest reads the existing `tsconfig` paths and runs the TypeScript as
written.

**Playwright, end-to-end, instead of unit tests.** It would have caught all
three defects, and it needs a running API, a database, a worker, and a browser
per run. The integration suite already covers the stack end to end from the Go
side; what is missing is the fast check that runs on every commit.

**Pure-node tests for the security modules only.** Half the harness for less
than half the value: cheaper to install and blind to exactly the defects that
got through.

**Nothing, and rely on review.** This is the status quo, and the three defects
above are its measured result.

## Consequences

**What becomes possible.** A defect in the session boundary or in mode-derived
UI fails a check rather than reaching a person. The security-relevant modules
get to state their invariants where the invariant lives.

**What becomes harder.** Four dev dependencies, a config file, and a slower
`make check`. Component tests that assert on rendered structure will need
updating when that structure changes — which is the cost of testing behaviour
through a DOM, and is why the scope above is narrow.

**What is explicitly not solved.** This is not end-to-end coverage. It does not
exercise a real API, a real database, or a real browser, and it cannot catch a
defect that only appears when those are wired together — the stale-container
class of problem stays a deployment concern. Nor does it catch the Tailwind
font-size collision: jsdom does not resolve utility classes, so that one is
prevented by a token name (`--color-inverse`) rather than by a test.
