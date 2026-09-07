# ADR 038: Kubernetes lands in two steps, and a scan becomes a Job in the second

- **Status:** Accepted — approved 2026-09-07; 12a implements the first half
- **Date:** 2026-09-07
- **Amends:** [ADR 004](004-scanner-isolation.md)

## Context

Phase 12 is named in CLAUDE.md §26 as "Kubernetes: images, deployments, scanner
Jobs, limits, security contexts, network policies, Helm". That is one line
covering two different kinds of change, and treating it as one piece of work is
the mistake this ADR exists to avoid.

**What runs today.** `docker-compose.yml` starts five services. The worker is a
long-lived process that claims jobs from Redis and runs scanner binaries in
its own container, each scan in a workspace directory created and destroyed per
job. Isolation is container hardening: non-root, read-only root filesystem, all
capabilities dropped, `no-new-privileges`, a tmpfs workspace, and a distroless
API image with no shell.

**What waits here.** Every security item still outstanding, and they do not all
have the same shape:

| Item | State | What actually closes it |
|---|---|---|
| T-10 | **Open** — the only one | The worker image referenced by digest |
| T-08 | Partial | A sandbox rather than container hardening |
| T-51 | Partial | A per-scan filesystem with a size quota |
| `Capabilities.NetworkKinds` | Not enforced | A network policy that varies per scan |

The last two are the interesting ones, because both need something the current
design cannot express: a *per-scan* boundary. A long-lived worker has one
filesystem and one network namespace for every scan it will ever run, so a
policy derived from what *this* target needs has nowhere to attach. That is why
`NeedsNetwork` has existed since Phase 2 with no caller — verified, not assumed:
six adapters declare `NetworkKinds` honestly and nothing reads the declaration.

**And one non-security reason.** The GitHub Action shipped in Phase 10 cannot
run against a `localhost` stack, because GitHub's runners cannot reach one. The
Action is written, tested and merged, and is waiting on a hostname.

## Decision

**Phase 12 splits into 12a and 12b, and the split is on where the trust boundary
moves.**

### 12a — the platform runs on Kubernetes

Deployment configuration. **No Go code changes.**

- A Helm chart for `api`, `worker`, `postgres` and `redis`.
- **Images referenced by digest, not tag.** This is what closes T-10: the
  scanner binaries inside the worker image are already built from source at
  pinned commit SHAs (ADR 009, T-28), so pinning the image digest fixes exactly
  which of those binaries runs. A tag does not — it is mutable, which is the
  same objection this project already made to tags in the Dockerfile.
- `securityContext` on every pod: `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, all capabilities dropped, seccomp
  `RuntimeDefault`.
- `resources` requests and limits, so §14.3's CPU and memory bounds are enforced
  by the scheduler rather than by hope.
- A default-deny `NetworkPolicy` per workload, with egress opened only to what
  each provably needs: the API reaches PostgreSQL and Redis and nothing else.
- An Ingress, so the API has a hostname and the Action becomes usable.
- Credentials from Kubernetes Secrets. Nothing in the chart carries a default
  password, and the chart fails to render rather than inventing one.

### 12b — a scan becomes an ephemeral Job

This is the trust-boundary change, and it is where the two Partials close.

- The worker stops executing scanners and starts scheduling them: one Job per
  scan, which exits when the scan does.
- **A per-Job ephemeral volume with a `sizeLimit`.** This is what closes T-51's
  residue. The image size cap bounds the *compressed* size a manifest declares;
  a layer that decompresses far larger is today bounded only by the disk trivy
  extracts into. A quota on a volume that dies with the Job bounds it for real.
- **A per-Job NetworkPolicy derived from `Capabilities.NetworkKinds`.** The
  declaration becomes a control: a repository scan gets egress to the git host,
  an image scan to the registry, an endpoint scan to the target, and a
  filesystem scan gets none. Six adapters already carry the honest metadata.
- A result-return path, since the process producing the raw result is no longer
  the process holding the database connection.

## Why split rather than ship it whole

**12a changes no Go code and 12b changes how every scan executes.** Together
they would be one pull request that both introduces Kubernetes and rewrites the
worker, with no intermediate state where either half is verifiable. If the
result misbehaved, "is this the chart or the new execution model?" would have no
cheap answer.

**12a is worth having on its own.** It closes the only Open threat, hardens
every pod, and unblocks the Action — none of which depends on how a scan
executes.

**12b needs 12a to exist first.** Nothing can schedule a per-scan Job before the
platform runs on a cluster at all.

The precedent is this project's own: Phase 3 split into 3a and 3b, Phase 10 into
10a and 10b, both because a phase named as one line contained two decisions.
Recording the split beforehand is the difference between a deviation and drift
(§26).

## Alternatives considered

**One phase, one pull request.** Rejected above. The honest version of the
objection: I would not be able to tell you which half broke something.

**12b first, 12a after.** Incoherent — there is no cluster to schedule Jobs on.

**Skip Helm; ship plain manifests.** Genuinely tempting, and simpler to read.
Rejected because the limits are the point: a `values.yaml` is where CPU, memory,
volume size and replica counts become configuration a deployment can set, rather
than numbers edited into a manifest. That is the same rule §10 applies to risk
weights, and §12 to policy thresholds.

**Keep container hardening and never move to Jobs.** This would mean T-51 and
`NetworkKinds` stay open permanently, and saying so is better than leaving 12b
implied. It is a defensible position for a single-operator tool — but the
declaration already exists in the code, and metadata that will never be enforced
should be deleted rather than left looking like a control.

**Treat Kubernetes as the only deployment and drop compose.** Rejected. Compose
is the development loop and `make up` is in every contributor instruction; a
cluster is a poor place to iterate. Compose stays for development, the chart is
the deployed form, and neither claims to be the other.

## How this gets verified

Against a real cluster, locally, with `kind` — which is installed, while no
kubectl context is configured today. Nothing in 12a is reported as working on
the strength of a manifest parsing:

- the chart renders and applies,
- every pod reaches Ready,
- a scan submitted through the Ingress completes and is readable,
- and the security context is confirmed on a running pod rather than in the
  YAML that requested it.

The last one matters. A `readOnlyRootFilesystem: true` that a scanner then fails
against is a control that works and a product that does not, and the only way to
learn which is to run a scan.

## Consequences

**T-10 closes in 12a.** The one Open threat, and it closes on a digest.

**T-51 and `NetworkKinds` do not close in 12a**, and 12a must not claim they do.
They are 12b's, and until then the threat model keeps saying so.

**T-08 improves in both and closes in neither.** Seccomp and a per-Job
filesystem are stronger than what exists; they are still not a sandbox. It stays
Partial, which is the honest end state rather than a task.

**A new operational surface.** A Helm chart is code that grants privileges, and
a misconfigured `securityContext` is a security defect in a file nobody thinks
of as source. §24 already lists "changing Kubernetes privileges" as high-risk,
and the self-scan's trivy misconfiguration rules cover Kubernetes manifests —
they will apply to ours the moment the files exist.

**The Action becomes deployable, not deployed.** 12a gives the API a hostname in
a cluster; whether SecureOps is exposed to the public internet stays a separate
decision, and the threat model's note that "the SecureOps API is never exposed
to the user's network by this design" needs revisiting rather than quietly
contradicting.
