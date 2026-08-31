# ADR 008: The worker fetches repositories and hands adapters a filesystem target

- **Status:** Accepted
- **Date:** 2026-08-31

## Context

`POST /api/v1/scans` accepts a `repository` target. Nothing fetches it.

Phase 2 built the worker to create an ephemeral workspace per job and destroy it
afterwards, but the workspace is never given to an adapter, and no code clones
anything. `Scanner.Scan(ctx, target)` receives a target describing a *remote*
repository URL. So the first adapter has nowhere to look, and every scan of a
repository target fails before it starts.

Something has to turn `https://github.com/acme/app` into bytes on disk. The
question is what, and how the result reaches the adapter.

Fetching is also the single most dangerous operation in the platform. It is the
moment SecureOps pulls attacker-controlled content onto a machine it owns
(§14: the worker is the only component that touches untrusted target content),
and `git` is a large program with a long history of remote-triggered surprises.

## Decision

**The worker fetches. Adapters never do.**

Before dispatching any scanner, the worker clones a `repository` target into the
job's ephemeral workspace, then rewrites the target for the adapters:

```text
{Kind: repository, RepositoryURL: "https://…", Ref: "main"}
        │  worker clones into the ephemeral workspace
        ▼
{Kind: filesystem, Path: "<workspace>/repo"}
```

Adapters therefore only ever see a local path. This is why `KindFilesystem`
exists and why the API refuses to accept it from a client (see
`submittableKinds`): it is an internal, post-fetch kind, not a way for a caller
to point a scanner at the worker's disk.

The `Scanner` interface is unchanged. `Target.Path` already carries what an
adapter needs, so no adapter learns about fetching, credentials, or git.

### How the clone is bounded

Every one of these is a deliberate refusal of a capability git offers by
default:

| Control | Why |
|---|---|
| `--depth 1 --single-branch --no-tags` | Full history is enormous and rarely needed. History scanning, when added, opts in explicitly. |
| `--recurse-submodules=no` | A submodule is an attacker-controlled URL fetched on our behalf — SSRF that bypasses the target validator entirely. |
| `-c core.hooksPath=/dev/null` | Belt and braces. `git clone` does not run repository hooks, but the cost of asserting it is one flag. |
| `-c protocol.allow=never`, then `https`/`ssh` only | Blocks `ext::`, which executes an arbitrary command, and `file://`, which reads the worker's own disk. |
| `-c credential.helper=` (empty) | Prevents git consulting a credential helper and attaching the host's credentials to an attacker-chosen URL. |
| `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/true` | A private repository must fail fast, not block the worker forever on a password prompt. |
| Empty environment except an explicit allow-list | The subprocess must not inherit the database URL, Redis password, or cloud credentials (§14.7). |
| Hard timeout | A slow-drip remote is a denial of service against a worker slot. |
| Post-clone size and file-count limits | A repository is untrusted input, so it is bounded like any other (§15.8). Exceeding a limit is a structured failure. |
| Ref validated before use | Already enforced by `scanners.Target`: a ref beginning with `-` would be read by git as a flag rather than as data. |

The clone runs through `scanners.Run`, so it is an argument vector with no shell
anywhere in the path, exactly like a scanner invocation (§14.4, §25.11).

### Size limits are enforced after the clone, not during

`git clone` offers no reliable pre-flight size check — the remote reports what it
chooses to report. So the limit is applied to what actually landed, and the
workspace is destroyed on breach. This means a hostile repository can cause a
worker to write up to the limit before being stopped, which is accepted: the
limit is what bounds the damage, and the workspace is ephemeral and destroyed
either way.

## Alternatives considered

**Each adapter clones what it needs.** Rejected. It duplicates the most
security-sensitive code in the platform across every adapter, guarantees the
controls above drift apart, and makes each adapter depend on git. It also
re-fetches the same repository once per scanner, multiplying both the time and
the exposure.

**The API fetches and passes content to the worker.** Rejected outright. §14.1
is unambiguous: the API server never touches untrusted target content. This
would move the platform's most dangerous operation to its most exposed process.

**Use a Go git library (go-git) instead of the git binary.** Genuinely
attractive — no subprocess, no argument handling, and no `ext::` transport to
disable. Rejected for now on maturity grounds: go-git's protocol coverage and
performance on large repositories lag the reference implementation, and a fetch
that fails on real-world repositories is worse than one with a well-understood
attack surface. Worth revisiting if git's subprocess surface causes trouble.

**A shared repository cache across scans.** Rejected as premature, and
security-relevant rather than merely an optimisation: a cache shared between
projects is a path for one scanned repository's content to influence another's
scan. If it is ever added, it needs its own ADR and its own isolation argument.

## Consequences

- A scan of a repository target now has a fetch phase that can fail on its own,
  distinctly from any scanner failing. It gets its own `FailureReason`, so
  "we could not obtain the code" never reads as "we scanned it and found
  nothing" (§13).
- Only public repositories work. There is no credential handling, deliberately:
  storing per-project git credentials is real product surface — issuance,
  scoping, rotation — and it is not being invented as a side effect of this
  decision. Private repositories are a known limitation.
- Shallow clones mean secret scanning covers the working tree, not history. A
  credential committed and later removed is not detected. This is a real gap,
  recorded as such; history scanning is a follow-up that must opt in to the
  cost.
- The worker now needs `git` on its PATH. Its absence is reported as a
  structured failure like any missing scanner binary, not a crash.
