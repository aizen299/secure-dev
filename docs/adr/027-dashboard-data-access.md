# ADR 027: How the dashboard reads, and what it is allowed to do

- **Status:** Accepted
- **Date:** 2026-09-03

## Context

Phase 9 adds the dashboard. It is the first component that reads the API as a
client rather than as a test, and that raises three questions the API's own
design did not have to answer: where its credential lives, what that credential
is allowed to do, and who is allowed to look at the result.

None of these are styling questions, which is why they are recorded here rather
than settled in a component.

## Decision

### 1. Every API call is server-side. The token never reaches the browser

`apps/web/src/lib/api.ts` begins with `import "server-only"`. Every page is a
React Server Component, and the one browser-reachable route
(`/api/search`, which feeds the command palette) is a Next route handler that
runs in the same server process.

The credential is read from `SECUREOPS_API_TOKEN` in the server environment. No
component fetches the SecureOps API from the browser, so no token is ever
serialised into a page payload, and the `server-only` guard turns a mistaken
client import into a build failure rather than a credential leak.

The practical consequence is that the browser talks only to the dashboard, and
the dashboard talks to the API. The API is never exposed to the user's network
by this design, which also means the SecureOps API needs no CORS policy for it.

### 2. The dashboard holds a `viewer` token and is read-only

It reads. It does not dismiss findings, edit policy, or submit scans, and the
role it holds makes that structural rather than a matter of which buttons were
built (ADR 023).

The reason is not caution, it is honesty about identity. Phase 11 owns per-user
identity; until it lands, an action taken through the dashboard would be
attributed to the dashboard's own credential, not to the person who clicked. A
finding dismissed by "the dashboard" is an audit record that names nobody
(§15.6), and a policy edited by "the dashboard" is worse. The sidebar says the
view is read-only rather than leaving a reader to discover it by looking for a
button that is not there.

When Phase 11 brings identity, the dashboard gains writes and the credential
becomes the person's, not the process's.

### 3. Absence is rendered as absence

Three states that a dashboard usually collapses into one grey box are kept
distinct, because collapsing them is how an operator comes to distrust a screen:

- **No credential** is a deployment problem and says so, with the variable to
  set. Rendering an empty project list here would let someone read "no
  projects" when the truth is "cannot see any projects".
- **No data** is a real answer — a project with no scans has no risk score, and
  that is normal.
- **Unreachable** is a failure, and never looks like either of the above.

The same discipline runs down to individual fields. A finding with no EPSS
signal renders `—`, never `0%`: ADR 018 keeps "nobody measured this" distinct
from "unlikely" in the model, and the UI is where that distinction is most
easily thrown away.

### 4. Colour carries meaning, and nothing else is coloured

The interface is neutral greyscale except severity, gate verdict, and scan
state. A decorative accent anywhere else would compete with the only three
signals an operator has to read correctly under pressure.

The severity ramp varies in both hue and lightness — grey, blue, amber, orange,
red — so it survives greyscale and the common forms of colour blindness. The
gate verdict additionally carries an icon, because it is the value most likely
to be read at a glance and the one where colour alone would fail the reader on
the distinction that matters most.

### 5. Nothing computes a number the engines did not produce

The dashboard displays risk, it never derives it. Where a tempting aggregate
existed — "the score if every remediation action were taken" — it is **not**
shown, because `score_after` is computed per action independently and the
aggregation is max-dominant (ADR 019): the combined effect is not the sum, the
product, or the last value in the list. Showing one would mean inventing a
figure the risk engine never produced, in the one place a reader would most
reasonably trust it.

## Alternatives considered

**Fetch from the browser with a token scoped to the session.** The standard SPA
shape, and it requires the API to be reachable from the user's network and a
token to exist in browser memory. Both are new exposure in exchange for
interactions this read-only dashboard does not have.

**Give the dashboard a `service` or `admin` token so triage can happen in the
UI.** Rejected on the audit trail: every action would be attributed to the
dashboard rather than to a person, which is a worse record than no action at
all. This is what Phase 11 unblocks.

**Cache reads to make the dashboard feel faster.** Every read is `no-store`. A
page that renders a cached PASS after a FAIL has landed is worse than a page
that takes another two hundred milliseconds.

**A table library for the findings list.** Pulled in and then removed. What the
list needs is one comparator and one substring match over a bounded set; the
library's value is virtualization, grouping, and column visibility, none of
which are used, and its major versions rename their own API.

## Consequences

**What becomes possible.** Phases 4 through 8 become visible for the first
time. The risk score, the correlated issues, the ranked remediation plan, and
the gate's per-condition explanation had no reader before this.

**What this exposed.** Building the first real client found a bug nothing else
would have: `cmd/api/main.go` never wired the policy store, so
`GET /projects/{id}/policy`, `PUT` on the same path, and `GET /scans/{id}/gate`
had answered 503 from the real binary for the whole of Phase 8. The handler
tests construct their own `Options` with a policy store and passed throughout.
Fixed, with a test that asserts the binary wires every store rather than a list
someone has to remember to update.

**What becomes harder.** The dashboard is a second consumer of the API contract,
so an API change now breaks two things. That is the point of `docs/api/openapi.yaml`
and of the types mirroring it.

**What is explicitly not solved.** The dashboard has **no user authentication**:
anyone who can reach it sees every project's findings, because it holds one
credential on everyone's behalf (T-57). It is bound to loopback in the compose
file and that is a deployment convention, not a control. This is the same T-23
gap the API has, seen from the other side, and Phase 11 closes both.
