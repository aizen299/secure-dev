# Security review — 2026-09-08

The review CLAUDE.md §26 asks for at the end of Phase 14: the finished system
read against §14 (scanner isolation) and §15 (security requirements) as a whole,
rather than against the diff of any one change.

Two things make this different from the per-change reviews that preceded it.
It reads the rules in order and asks what enforces each one, rather than asking
whether today's change broke anything. And where a rule is enforced by
something checkable, the check is recorded here so the claim can be re-run
rather than re-argued.

Scope: `main` at the close of Phase 14. Phase 12b's scan-job machinery is
merged and **not deployable** (no volume for provisioned scanner data), so this
reviews the shipped default — scans run in-process in the worker.

---

## §14 — Scanner isolation

### §14.1 The API never executes untrusted content

**Enforced structurally, and verifiable.** The API binary does not link a single
scanner adapter:

```console
$ go list -deps ./cmd/api | grep internal/scanners
github.com/aizen299/secure-dev/internal/scanners
```

One line: the contract. Not `gitleaks`, `semgrep`, `trivy`, `zap`, `grype` or
`syft`. The API can describe a Target and cannot run anything against one — not
by convention but because the code to do so is not in the binary.

This is the rule most worth having a structural answer to, and it has one.

### §14.2 Execution happens only in workers

Holds. `internal/scanexec` and the adapters are reachable from `cmd/worker` and
`cmd/scanjob` and from nothing else that runs.

### §14.3 Per-execution limits

Non-root, read-only root filesystem, dropped capabilities, `no-new-privileges`,
a tmpfs workspace destroyed after the job, hard timeouts per scanner and per
job, and — under Kubernetes — scheduler-enforced CPU and memory limits and
default-deny network policies (12a, asserted by `make lint-chart` in CI).

**Partial, and honestly so.** These are container-hardening measures, not a
sandbox (T-08). Phase 12b would add a per-scan filesystem quota and a per-scan
network policy; it is merged and unshipped.

### §14.4 Never invoke a scanner through a shell

**Holds, checked rather than assumed:**

```console
$ grep -rE '"sh", "-c"|"bash", "-c"|exec\.Command\("sh"' --include="*.go" .
(no matches outside tests)
```

Every adapter goes through `scanners.Run` with an argument vector.

### §14.5 Path canonicalisation · §14.6 SSRF

Both hold. `netguard` refuses loopback, link-local and private ranges for every
target kind — including `image`, which went without it until an adapter served
that kind and T-49 caught it. That history is the reason the endpoint and image
paths were audited rather than assumed when each landed.

### §14.7 Workers hold least privilege

**Partial, and this is the sharpest remaining gap in §14.**

No registry credentials, no cloud credentials — verified: nothing in the tree
reads `DOCKER_PASSWORD`, `AWS_*`, `GCP_*` or `AZURE_*`. Image scanning is
public-registry only as a consequence.

But the worker holds the platform's **database** credential while executing
scanner binaries against hostile content. That is T-18, and Phase 12b exists to
end it: a scan running as an ephemeral Job holds no database, queue or cluster
credential at all. Merged, not deployable.

---

## §15 — Security requirements

### §15.1 No hard-coded credentials

**Holds, checked:**

```console
$ grep -rE '(password|secret|token) *[:=] *"[A-Za-z0-9]{12,}"' --include="*.go" .
(no matches outside tests)
```

`gitleaks` runs over the whole history and the working tree on every CI run and
before every commit (`make security`), which is a stronger and continuous form
of the same check.

### §15.2 No committed `.env` or key material

Holds. `.gitignore` covers `.env*`, and `make scan-secrets` refuses to run if a
local env file is present but not ignored — the guard is verified rather than
trusted, because the working-tree scan excludes those paths.

Extended in Phase 12b after a 65 MB `worker` binary reached `git add -A`: a bare
`go build ./cmd/<name>` writes to the repository root, which `/bin/` did not
cover. All six binary names are now ignored.

### §15.3 Never log secrets or raw secret evidence

Holds, and it is a design property rather than a discipline. A detected secret's
**value is never stored at all** — Gitleaks output is redacted before
persistence (ADR 007), Trivy's is rewritten (ADR 015), ZAP's is redacted
(ADR 026), and each control has a test that fails if the redaction is removed.
Stored failure reasons are fixed summaries; the detail goes to logs.

That last split was found to cut the wrong way once, in Phase 12b: a fatal
executor error recorded "the worker could not create an isolated workspace" and
logged nothing, which is safe and undiagnosable. The reason is still fixed; the
error is now logged beside it.

### §15.4 Server-side authn and authz on every request

Holds. Both a person's session and a machine token are resolved server-side, and
authorization is enforced in the project middleware, in the `GET /projects`
query, and on the id-addressed endpoints that carry no project in the URL.

The dashboard forwards the person's own session rather than its own credential
(ADR 027, ADR 033), so a viewer reads what a viewer may read and the audit trail
names the person.

### §15.5 RBAC roles

Holds with a documented deviation. The specification names four roles; the
system has three — `admin`, `security`, `viewer` — because Developer and Viewer
would have had identical permissions here. Recorded in ADR 033 rather than
silently collapsed.

**`admin` is global by construction.** An administrator reaches every project,
so there is no per-project administrator. A deliberate simplification for a
single-team tool.

### §15.6 Audit security-sensitive actions

Holds. Scan creation, project changes, policy changes, finding transitions and
user/role changes are written to an append-only log in the **same transaction**
as the change — `audit.Write` takes a transaction, not a pool, so a change
cannot land without its record.

One defect worth remembering: policy edits recorded a token label instead of the
person for several weeks, because that handler built its actor by hand rather
than through the shared helper. Found by a user asking why their own change was
attributed to a client.

### §15.7 Everything is untrusted input

Holds, including the case people forget: **scanner output itself**. Every parser
is fixture-tested against malformed, truncated, empty and hostile input, and a
scanner that produces unparseable output degrades its own result rather than
failing the scan.

The job payload is re-validated on arrival even though the API validated it —
the payload crossed a trust boundary, and a target that was valid at enqueue
time may not be now.

### §15.8 Bound every external input

Holds. Request bodies, scanner output, fetched repositories (size, file count,
timeout), image size, SBOM component count, and — added in Phase 12b — the
scan-job result channel, which is bounded before a body is read rather than
after.

### §15.9 Parameterised SQL only

**Holds, checked:**

```console
$ grep -rE 'Query\(ctx, *"[^"]*" *\+|Exec\(ctx, *fmt\.Sprintf' --include="*.go" .
(no matches outside tests)
```

pgx's extended protocol refuses concatenated multi-statement text, which
enforces the rule structurally rather than by review.

### §15.10 Containers run as non-root

**Holds in every image:**

```console
api.Dockerfile      USER nonroot:nonroot
worker.Dockerfile   USER nonroot:nonroot
web.Dockerfile      USER node
```

Under Kubernetes this is additionally enforced by `runAsNonRoot` on the pod
spec, asserted by `make lint-chart` in CI — so an image regression would be
caught by the platform rather than only by the Dockerfile.

### §15.11 Least privilege everywhere

Partial. CI tokens are minimal and third-party actions are SHA-pinned; the
Kubernetes RBAC for the controller is a namespaced Role with no secrets access
and no `pods/exec`. The database role is the gap (§14.7, T-18).

### §15.12 Never disable a control to make something pass

Holds, and was tested by circumstance. Phase 12b needed a locally built image to
carry a digest, which the chart requires; the tempting fix was an `allowTags`
escape hatch "just for development". Instead the local cluster runs a registry
so the requirement is satisfied honestly.

### §15.13 No security through obscurity · §15.14 Threat model maintained

Both hold. The threat model was re-read end to end in this phase, which is what
found three entries **understating** their own posture — the drift nobody looks
for.

### §15.15 Trust boundary chain

Documented in `trust-boundaries.md` and unchanged in shape:
`User → Web UI → API → Orchestrator → Worker → Untrusted Repository`.

---

## What this review did not do

It read the system as it stands, not as it would be with Phase 12b deployed.
Every claim about scan-job isolation in this document is about code that is
merged and switched off.

It did not re-derive the risk weights, which remain uncalibrated against real
estates — that needs evidence rather than review.

And it is a reading, not a penetration test. Nobody has attacked this system.
