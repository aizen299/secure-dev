# Running SecureOps on Kubernetes

Phase 12a: the platform runs on a cluster. A scan still executes inside the
long-lived worker — moving it into a per-scan Job is 12b
([ADR 038](../../docs/adr/038-kubernetes-in-two-steps.md)).

`docker-compose.yml` at the repository root remains the development loop. This
chart is the deployed form. Neither claims to be the other.

## Quick start, locally

```bash
make kind-up       # a kind cluster plus a registry beside it
make kind-deploy   # build, push by digest, install
make kind-down     # remove both
```

## Images are pinned by digest, and a tag is refused

The chart will not render an image reference that is not a digest:

```
Error: every image needs an explicit digest: set images.<name>.digest to a
sha256:... value. A tag does not pin which scanner binaries run (threat model T-10).
```

This is the control that closes **T-10**, the project's last Open threat. The
scanner binaries inside the worker image are already built from source at pinned
commit SHAs ([ADR 009](../../docs/adr/009-build-scanners-from-source.md)); the
image digest is what carries that pin into a cluster. A tag can be repointed at
different bytes after review.

There is deliberately **no escape hatch** — no `allowTags`, no "development
mode". An escape hatch is how a control becomes optional. That is why
`make kind-up` runs a registry: a locally built image has no digest until
something serves it, so local development satisfies the requirement honestly
rather than switching it off (CLAUDE.md §15.12).

## What the chart deploys

| Workload | Kind | Notes |
|---|---|---|
| `api` | Deployment | No internet egress at all — it orchestrates and never touches a target (§14.1) |
| `worker` | StatefulSet | Each replica gets its own cache volume; grype's database is ~2 GB |
| `web` | Deployment | Reaches the API and nothing else |
| `postgres` | StatefulSet | Optional — disable it and point at your own |
| `redis` | Deployment | No persistence: the queue is transient, durable state is in PostgreSQL |

Migrations run as an **initContainer** on the API and the worker, not as a Helm
hook. A pre-install hook runs before every normal resource, so it would start
before both the Secret holding its credentials and PostgreSQL itself existed —
both found by deploying it. golang-migrate takes `pg_advisory_lock` around the
migration (checked in v4.19.1), so concurrent replicas serialise, and the
initContainer gives dependency ordering for free.

## Security posture

Applied to every pod and asserted by `make lint-chart`:

- `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  all capabilities dropped, seccomp `RuntimeDefault`
- CPU and memory requests and limits on every container, initContainers included
- Default-deny `NetworkPolicy` in both directions, with each workload allowed
  only what it provably needs

`postgres` and `redis` run as their images' own uids (70 and 999) rather than
the chart-wide 65532, because we do not build those images and forcing another
user leaves their data directories unreadable. That is the one place a workload
does not take the shared context, and it is stated rather than silent.

### What the network policy does and does not do

The worker must reach arbitrary public hosts: it clones repositories, pulls
images from public registries, and crawls the endpoint a DAST scan names. What
this policy *can* do is keep it out of everything that is not public — the
cluster network and the link-local address that serves cloud instance
credentials are excepted from its egress. That is defence in depth behind
`netguard`, which already refuses those ranges when a target is validated
(T-04, T-49, T-56).

Per-scan egress — a filesystem scan getting no network at all, derived from each
adapter's declared `Capabilities.NetworkKinds` — needs a pod per scan and is
12b.

**A NetworkPolicy is only enforced if your CNI implements it.** Confirm rather
than assume: on a cluster that ignores them, these objects apply cleanly and do
nothing. kind v0.32's kindnet does enforce them, verified by connecting.

## Credentials

Nothing is defaulted. The chart refuses to render without
`secrets.postgresPassword`, `secrets.redisPassword`, `secrets.apiTokens` and
`secrets.dashboardToken` — the same line `docker-compose.yml` holds with
`${VAR:?}`, because a default password is a known-weak credential that every
deployment inherits and nobody notices.

For a real deployment set `secrets.existingSecret` and manage the Secret with
whatever holds your secrets, so credentials never pass through a values file.

## Exposing the API

`ingress.enabled` is `false` by default. The threat model records that "the
SecureOps API is never exposed to the user's network by this design"; enabling
an Ingress changes that sentence deliberately, which is why it is an act rather
than a default.

The API and dashboard get separate hosts rather than paths on one. Sharing an
origin would put the dashboard's session cookie on the same origin as the API
and let the browser call it directly — the opposite of
[ADR 027](../../docs/adr/027-dashboard-data-access.md).

Once the API has a hostname, the GitHub Action shipped in Phase 10 can reach it.
Give CI a `service` token scoped to its own projects: it is the most widely
distributed credential you have, and it must not be able to switch off the gate
that judges it.
