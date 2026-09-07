# ADR 036: The CI client is a standalone binary, and its exit code is the contract

- **Status:** Proposed
- **Date:** 2026-09-07

## Context

The gate has produced a verdict since Phase 8 and nothing carries it anywhere.
SecureOps can tell you a build should fail; it cannot fail one. That is the
largest functional gap in the product and the whole of Phase 10.

Everything the decision needs already exists. `GET /api/v1/scans/{id}/gate`
returns the verdict, every condition with its explanation, and a coverage record
saying whether the scan was complete and whether incompleteness changed the
answer. A `service` token can submit a scan and cannot edit the policy judging
it (ADR 023), scoped to its own projects (ADR 033). What is missing is a client.

The specification names `cmd/cli/` and nothing else about it. This ADR decides
the parts that are load-bearing: what the binary is, and what its exit code
means.

## Decision

### 1. A standalone binary, with the Action as a thin wrapper

`cmd/cli/` is a program anybody can run — a laptop, a Jenkins job, a Makefile,
GitLab. The GitHub Action wraps it and adds nothing but the plumbing GitHub
needs.

The alternative — logic inside a JavaScript action — makes the CI path testable
only by pushing to GitHub. That is the same reason the scan API exists
separately from the dashboard: a path you can only exercise through a UI is a
path that gets exercised rarely and debugged badly. It would also tie SecureOps
to one CI provider in the layer that decides whether a build fails.

### 2. Three exit codes, and the third is the point

```text
0   the gate did not block:  PASS, or WARN
1   the gate blocked:        FAIL
2   the gate did not run:    unreachable, timed out, refused, scan failed
```

**Exit 2 exists so a broken client cannot pass a build.** This is the security
property the whole binary turns on. A client that exits 0 when it cannot reach
the API converts an outage — or a network someone shaped deliberately — into a
silent, universal disabling of the gate for every repository that uses it. §12
already refuses to let a PARTIAL scan evaluate as a complete one; the same
reasoning has to survive the trip into CI, where the failure is invisible
because the build is green.

It is distinct from exit 1 rather than folded into it, because the two demand
different responses. Exit 1 means fix the code. Exit 2 means fix the pipeline,
and a team that cannot tell them apart will eventually treat both as flakiness.

**WARN exits 0**, deliberately. WARN exists because a team chose `warn` for that
rule; making it block would make it a FAIL with a friendlier name and leave the
policy engine's two levels indistinguishable to the only consumer that acts on
them. A team that wants a rule to block sets that rule to `fail` — policy is
data (§12), and a `--fail-on-warn` flag would be a second place to decide
severity, with the CLI's copy silently outranking the project's.

### 3. It waits, because scans are asynchronous

`POST /scans` returns 202 (§13). The client polls `GET /scans/{id}` until the
scan settles, bounded by `--timeout`. A timeout is exit 2, not exit 0: a scan
that has not finished has not passed, and a client that assumed otherwise would
pass every build that was slow enough.

Polling rather than holding a request open, for the reason §13 gives: the HTTP
request must never block on scanner execution, and a CI client is not an
exception to that.

### 4. Both renderings come from one evaluation

`--format json` emits the gate result as the API returned it. The default is
human-readable text. Both are rendered from the same conditions, so a PR comment
and a status check cannot disagree about why a build failed — the property §12
requires and the reason the API returns conditions rather than a bare verdict.

Every rule is printed, breached or not. A report listing only breaches makes
"this project is clean" and "this policy checks nothing" look identical.

### 5. Degraded coverage is reported, never inferred

The gate already refuses to store PASS for a scan that is not `completed`. The
client's job is to say so: a WARN caused by a crashed scanner reads differently
from one caused by a breached rule, and `Coverage.Downgraded` is exactly that
distinction. Printing the verdict without it would hide a scan that found less
than it should have behind a word that sounds like a judgement.

### 6. The credential is a scoped `service` token

Given as `SECUREOPS_API_TOKEN`, never a flag: a flag is visible in `ps` and in
CI logs, which is the same reasoning `cmd/useradd` follows for passwords
(ADR 033).

`service`, not `admin`, so the credential most widely distributed across an
organisation cannot switch off the gate judging it (ADR 023). Scoped to its own
projects, so a leaked CI token does not read every project's findings
(ADR 033).

**Never exposed to a `pull_request` workflow from a fork** (§16). The Action
documents this rather than working around it: a fork PR that could read the
token could exfiltrate it, and no gate result is worth that.

### 7. What this ADR does not decide

- **PR comments and status checks.** They consume the JSON this produces and are
  the second change, not this one.
- **Whether SecureOps gates its own repository.** Dogfooding is §16's
  requirement and worth doing, but a self-gating pipeline that fails is a
  pipeline that cannot merge its own fix.

## Amendment, 2026-09-07: the Action reports and does not block

§7 left two questions open. The project owner has answered the first: **the
GitHub Action operates in report-only mode.**

Report-only is implemented as a default, not as a property of the code. The
Action takes `fail-on-gate`, defaulting to `false`, and the check surfaces the
gate's real result either way -- a red check when the gate blocked, a green one
when it did not.

The alternative, and the reason it was rejected: an Action that swallowed the
exit code would be permanently green. A check that is always green is a check
nobody reads, and making it block later would be a code change rather than a
setting. Whether a verdict stops a merge belongs in branch protection, for the
same reason a policy's thresholds belong in the policy -- it is configuration,
and §12 already refuses to put that kind of decision in code.

So the exit-code contract in §2 is preserved rather than bypassed: the Action
runs the client, reports what it said, and does not act on it unless asked to.

**A limit worth stating plainly, because it is not obvious from the code.** This
Action cannot be exercised against this repository yet: the API runs on
localhost and GitHub's runners cannot reach it. It is written against the
client's contract and tested against that contract, and the parts only GitHub
can exercise -- posting a comment, setting a status -- are unverified until the
API has a hostname (Phase 12). That is a real gap, recorded here rather than
discovered later.

## Alternatives considered

**Logic in a JavaScript action.** Fewer moving parts for GitHub users and worse
for everyone else: untestable outside GitHub, unusable from any other CI, and it
puts the decision to fail a build in a layer nobody can run locally.

**Exit 0 on anything that is not FAIL.** Simpler, and it is the failure this
whole ADR exists to prevent: an unreachable API would pass every build silently.

**One non-zero code for everything.** Collapses "your code has a critical
vulnerability" into "the network was down". Both stop the build; only one is
about the code, and a team that cannot distinguish them learns to retry until
green — which is how a control gets routed around (ADR 024's reasoning).

**Blocking the request until the scan finishes.** Would remove the polling loop
and violate §13, which is architectural rather than stylistic: a scan can run
for ten minutes and an HTTP request that waits for it is a request that dies to
a proxy timeout somewhere with no result recorded.

## Consequences

**What becomes possible.** A build can fail on a security verdict, which is what
the preceding nine phases were for. The scoped `service` token from ADR 033
finally has the consumer it was built for.

**What becomes harder.** The exit-code contract is now public. Changing what a
code means silently breaks every pipeline using it, so it joins the API contract
as something that changes only with a version.

**A new trust surface.** CI is attack surface (§16). The Action must default to
`permissions: contents: read`, pin third-party actions to commit SHAs, and never
expose the token to fork PRs. The threat model gains an entry for the CI client
rather than assuming the API's existing entries cover it.

**Dogfooding stays deliberate.** SecureOps scanning SecureOps is already in the
pipeline as `make security`; gating on its own verdict is a separate decision
with a bootstrapping problem attached, and this ADR does not make it.
