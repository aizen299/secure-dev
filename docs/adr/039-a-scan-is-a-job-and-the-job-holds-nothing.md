# ADR 039: A scan runs in an ephemeral Job, and that Job holds no credentials

- **Status:** Accepted — approved 2026-09-07; built in three changes, this is the first
- **Date:** 2026-09-07
- **Implements:** [ADR 038](038-kubernetes-in-two-steps.md) §12b
- **Amends:** [ADR 004](004-scanner-isolation.md)

## Context

12a put the platform on a cluster and closed T-10. Two items were explicitly
left for 12b because neither is reachable while one long-lived process runs
every scan:

- **T-51** — the image cap bounds the *compressed* size a manifest declares. A
  layer that decompresses far larger is bounded only by the disk trivy extracts
  into.
- **`Capabilities.NetworkKinds`** — six adapters declare which target kinds need
  egress and `NeedsNetwork` has no non-test caller. Verified, not assumed.

Both need a boundary that exists per scan. A worker has one filesystem and one
network namespace for every scan it will ever run, so a quota or a policy
derived from *this* target has nothing to attach to.

**Reading the code for this turned up something larger than the two items.**
Today `internal/worker` does two jobs that the threat model treats very
differently. It executes scanner binaries against hostile content — and it holds
the database password, the Redis password, and the connection pool that writes
every finding. §14.7 says workers hold least privilege; they hold the platform's
data credential.

That was acceptable when there was nowhere else to put it. On a cluster there
is.

## Decision

**Split the worker in two along the line the trust model already draws, and make
the half that touches untrusted content hold nothing.**

### 1. Two components, not one

**The scan controller** (`internal/worker`, renamed in the deployment, not
rewritten). Consumes the queue, creates one Kubernetes Job per scan, waits for
it, ingests its output, and runs everything after: normalization, dedup,
correlation, risk, remediation, the gate, and all persistence. It never
executes a scanner and never fetches a repository.

**The scan job** (`cmd/scanjob`, new). One pod per scan. Fetches the target into
an ephemeral workspace, runs the selected adapters, emits raw results, exits.

What the scan job holds: nothing.

```text
                       database   redis   kubernetes   scanner binaries
scan controller           yes      yes    create Job         no
scan job                   no       no        no            yes
```

`automountServiceAccountToken: false` on the Job, so a compromised scanner
cannot even ask the API server who it is.

This is the part worth arguing about, so it is stated plainly: **12b is not
mainly a packaging change, it is the removal of a database credential from the
process that runs attacker-influenced binaries.** The two roadmap items come
along with it.

### 2. The controller creates Jobs; nothing untrusted can

Giving the component that runs untrusted content the ability to create Pods is
a textbook escalation — a compromised scanner would write its own privileged
pod. So the privilege goes to the half that touches nothing hostile, and it is
scoped to the narrowest RBAC that works: `create`, `get`, `list`, `watch` and
`delete` on `jobs` and `pods` in **one namespace**, and nothing else. No
`create` on anything with a service account, no `escalate`, no cluster role.

The Job's shape is not caller-controlled. The controller renders it from a
fixed template and injects only the target and the scanner selection, both of
which are already re-validated on arrival (§15.7).

### 3. Results come back over HTTP, with a token that dies with the scan

The scan job POSTs each raw result to the controller. The controller generates a
single-use token per scan, injects it into the Job, and accepts it for that scan
id only until the Job ends.

Raw output is up to 64 MB per scanner (`SECUREOPS_SCANNER_MAX_OUTPUT_BYTES`),
six scanners a scan, so this is a bulk channel and the alternatives were weighed
against that.

The controller is already the component that parses these bytes, so this adds no
new class of untrusted input — only a new door for it. That door is
size-capped before the body is read, authenticated, and bound to one scan.

### 4. The Job's filesystem is a quota — T-51

The workspace is an `emptyDir` with a `sizeLimit`, on a pod that dies with the
scan. A layer that decompresses past the quota is evicted by the kubelet, which
is a structured failure and a `PARTIAL` scan rather than a full node disk.

This is what closes T-51, and it closes it because the volume is per scan. A
shared worker volume can only be sized for the worst case of every scan at once.

### 5. The Job's network policy is derived from `NetworkKinds` — the declaration becomes a control

The controller reads `Capabilities.NetworkKinds` for the adapters it selected
and renders the Job's policy from it:

| Scan | Egress |
|---|---|
| filesystem-only adapters | **none at all** |
| repository | the fetch needs it; public, minus private ranges |
| image | as above, for the registry |
| endpoint | as above, for the target |

The first row is the point. A scan whose adapters declare no network gets a pod
that cannot open an outbound connection — which no deployment-level policy can
express, because the same worker also runs the scans that do need one.

**What this does not do, stated so it is not read as more:** the other three
rows are still "the public internet minus private ranges", the same as 12a. A
NetworkPolicy selects on CIDRs, not names, so narrowing to *this* git host needs
either IPs resolved at Job creation — which a rebind can defeat — or an
FQDN-aware CNI or egress proxy. That is a further step and is not this one.

## Alternatives considered

**Keep one worker; add a quota and a policy to it.** This is the shape that
looks cheapest and it does not work: a single pod has one filesystem and one
network namespace, so both controls would have to be sized and opened for the
most demanding scan the deployment ever runs. That is 12a, which is already
done.

**Let the scan job write to PostgreSQL directly, with a restricted role.** Row
level security on `scan_results` could confine it to its own scan. Rejected:
it keeps a database credential inside the pod running untrusted binaries, which
is the thing this ADR exists to remove, and it trades a removed credential for a
policy that has to be right forever.

**Return results through Redis.** The queue already exists, so no new channel.
Rejected for the same reason plus a worse one: a Redis credential in the scan
job would let a compromised scanner read and write *other* scans' payloads. The
blast radius is larger than the database case, not smaller.

**Return results through the Job's pod logs.** Genuinely appealing — the
controller already has `get pods`, so the Job needs no credential and no network
at all. Rejected on the bytes: logs are line-oriented, rotated by the kubelet at
a size the cluster owner sets, and not binary-safe. A 64 MB result would be
silently truncated, and §8 requires raw output be persisted verbatim.

**Object storage for results.** Clean, and adds a datastore. §25.14 forbids that
without a concrete requirement, and "somewhere to put bytes for ninety seconds"
is not one.

**A sidecar that ships results, sharing an `emptyDir` with the scan container.**
Keeps the credential out of the scanner's container. Rejected because it is in
the same pod: same node, same localhost, a shared writable volume. It looks like
a boundary and is not one.

**Do not split the worker; only add the Job.** That is, the worker creates Jobs
*and* keeps executing some scans. Rejected as the worst of both — the escalation
path of §2 with none of the benefit.

## Consequences

**What closes.** T-51 becomes Mitigated. `NetworkKinds` becomes a control for
the case that matters most. And the untrusted half of the system stops holding
the platform's data credential, which is a change to T-06, T-08 and T-18 that
none of them asked for.

**What gets worse.** Latency: a scan now waits for a pod to schedule and an
image to be present. On a warm node that is seconds; on a cold one it is the
worker image, which is large. This is a real cost and the honest mitigation is
that scans are already asynchronous by design (§13).

**A new dependency.** The controller needs a Kubernetes client. `client-go` is
large and pulls a great deal with it; §25.14 requires that be justified rather
than assumed, and the justification is that there is no way to create a Job
without it. It belongs to the controller alone — `cmd/scanjob` must not import
it, and nothing in `internal/scanners` may.

**A deployment that is not Kubernetes.** `docker-compose` is the development
loop and cannot create Jobs. The runner therefore keeps its in-process execution
path, selected by configuration, and the compose stack keeps using it. That is
two code paths for one thing, which is a real cost — the alternative is that
`make up` stops working, and a change that breaks the development loop to
improve production is not a good trade for a project this size.

**What stays Partial.** T-08. A pod with a quota and a policy is better isolated
than a shared worker and is still not a sandbox. Saying otherwise would be the
same overclaim this document has avoided elsewhere.
