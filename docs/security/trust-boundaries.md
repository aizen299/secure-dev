# Trust Boundaries

Every arrow in this chain crosses a boundary where data changes trust level.
Controls belong *at* the boundary, on the receiving side, because the sender is
never the thing you can rely on.

```text
User ──1──► Web UI ──2──► API ──3──► Queue ──4──► Worker ──5──► Untrusted target
                           │                        │
                           └──6──► PostgreSQL ◄──6──┘
```

| # | Boundary | Crossing it | Trust of the input |
|---|---|---|---|
| 1 | User → Web UI | Browser interaction | Untrusted |
| 2 | Web UI → API | HTTP requests | Untrusted |
| 3 | API → Queue | Scan job payloads | Untrusted on read |
| 4 | Queue → Worker | Scan job payloads | Untrusted on read |
| 5 | Worker → Target | Repositories, images, endpoints, **and scanner output** | Hostile |
| 6 | Services → PostgreSQL | SQL | Parameterised only |
| 7 | Stored conclusions → readers | Findings, issues, risk scores | Derived, and served back out |

## 1–2. User and Web UI → API

The UI is not a security control. It runs on the user's machine and anything it
enforces can be bypassed by talking to the API directly. Every restriction that
matters is enforced server-side (CLAUDE.md §15.4).

Controls: input validation on every field, size caps on every parse, a
structured error envelope that never echoes attacker input, security response
headers, server-generated request IDs (a client-supplied `X-Request-Id` is
discarded so log correlation cannot be poisoned).

**Not yet implemented:** authentication and authorization. Every endpoint is
currently public. See `threat-model.md` T-11.

## 3–4. API → Queue → Worker

This is the boundary that keeps untrusted content away from the API process.

The API **never executes target content** — no scanners, no builds, no package
manager installs, no git hooks. It validates, persists, and enqueues. That is
the whole of its involvement (§14.1).

Job payloads are plain data: a scan ID, a validated target, scanner names. A
payload never carries a command line, a script, or anything else a worker would
execute. `TestJobPayloadCarriesNoExecutableFields` fails if an executable-looking
field is ever added to the struct.

The worker **re-validates every payload on arrival**. SecureOps wrote the
message, but that is not a reason to trust it: the payload may have been sitting
in Redis, and a target that resolved to a public address at enqueue time may
resolve to a loopback address now.

## 5. Worker → Untrusted target

The only boundary where hostile content is actually touched, and the only place
scanner binaries run.

Controls, layered so each assumes the one above it failed:

- **Input** — allow-listed schemes (no `file://`, no `git://`), path containment
  inside the workspace, rejection of values beginning with `-`
- **Network** — SSRF policy at resolution *and* at dial time
- **Process** — `exec.CommandContext` with an argument vector; no shell anywhere
- **Environment** — explicit allow-list; the worker's own credentials are never
  inherited by a scanner subprocess
- **Filesystem** — ephemeral `0700` workspace, destroyed when the job ends
- **Resource** — per-scanner timeout, output cap that terminates the process,
  job timeout, concurrency cap
- **Process tree** — child runs in its own process group; the group is killed
- **Container** — non-root, read-only rootfs, all capabilities dropped, tmpfs
  workspace

Scanner *output* is untrusted too. A compromised or malicious scanner can emit
hostile output, so parsing is bounded and validated (§15.7).

## 6. Services → PostgreSQL

Parameterised statements only. pgx's extended protocol will not execute a
concatenated multi-statement string, which makes the rule enforceable rather
than a convention.

Workers hold least privilege: no database superuser, no cloud credentials, no
registry write access.

## 7. Stored findings and derived views

New with Phases 4-6, and a boundary in a different sense from the others: not a
place where data crosses between components, but a place where SecureOps'
*conclusions* accumulate and are served back out.

What crosses it: the durable findings record, the correlated issues derived from
it, the exploitation likelihood attached to both, and the risk score derived
from all three. Scan-time data is
observations about one repository at one moment; this is a maintained,
deduplicated, ranked inventory that outlives every scan that fed it.

Why it is drawn separately. The controls that matter here are not the ones that
matter at Boundary 5. Isolation and argv-only execution protect the act of
scanning; they say nothing about who may read the result, how long a conclusion
survives after it stops being true, or whether a derived view discloses more
than the data it was derived from. All three of those are live questions the
moment findings persist.

Reading is gated by authentication (T-11) and nothing finer — every valid token
reaches every project (T-23), which is why the impact of that gap grew with this
boundary rather than staying where Phase 3 left it. See T-36, T-37, T-38.

## When to update this document

Whenever a boundary moves: a new component, a new datastore, a change to what
executes untrusted content, or a change to how components authenticate to each
other (§21).
