# ADR 040: Provisioned scanner data ships in the image, pinned by digest

- **Status:** Accepted — approved 2026-09-08, verified on a cluster the same day
- **Date:** 2026-09-08
- **Amends:** [ADR 012](012-vulnerability-database-provisioning.md), [ADR 039](039-a-scan-is-a-job-and-the-job-holds-nothing.md) §6

## Context

Phase 12b stopped one step from shipping. A scan runs in a pod holding no
credentials, and for a repository target that pod has **no network egress at
all** — verified on a cluster. Then three of five scanners fail in it, because
grype, semgrep and trivy each need provisioned data and a pod with no network
cannot fetch it.

That is the isolation working. It is also why the mode is off by default and the
chart does not wire it.

ADR 039 §6 answered this with a `ReadOnlyMany` volume populated by a separate
job. That answer was written before anything ran, and two things have since
changed it.

**It anticipated grype's database and the requirement is wider.** The three
adapters that failed are exactly the three implementing `Provision`. Semgrep
needs rulesets, trivy needs a checks bundle and — for image targets — its own
vulnerability database.

**The storage requirement is the real blocker.** A multi-reader volume is not
available on kind's default storage class and is not the default on most
clusters. A chart that demands one fails on other people's infrastructure, which
is the least defensible way for a security control to be unavailable.

## Decision

**Provisioned scanner data is built into a dedicated scan-job image, refreshed
on a cadence, and selected by digest like every other image.**

### 1. Why this is not what ADR 012 rejected

ADR 012 refused to bake grype's database into an image, on the grounds that a
baked database is stale the moment the image is built, and a scan against stale
vulnerability data is a false clean — it succeeds, reports fewer vulnerabilities
than exist, and signals nothing (T-31). That reasoning stands and this decision
does not contradict it, because the comparison has changed.

Provisioning runs **once at worker startup and never refreshes** — verified, not
assumed: `registry.Provision(ctx)` has exactly one caller and there is no
periodic refresh anywhere. So today's staleness is *the worker's uptime*, which
on a stable deployment is weeks and is invisible.

A daily-rebuilt image is at most a day stale, and its age is **visible in the
digest**. That is not worse than the status quo; on any deployment that does not
restart daily it is better. What ADR 012 was really objecting to was staleness
nobody could see, and a content-addressed image is the opposite of that.

### 2. Read-only is sufficient, and was tested before this was written

Each scanner was run against its data mounted read-only, on a container with a
read-only root filesystem:

| Scanner | Result | Writable directory required |
|---|---|---|
| grype | scans, database reports `valid: true` | none |
| trivy | scans, valid JSON output | `tmp` |
| semgrep | scans, rules parse, clean stderr | `HOME` and `TMPDIR` |

The writable directories are supplied by an `emptyDir` mounted over those paths,
leaving the data itself immutable. This matters beyond convenience: the pod that
runs untrusted binaries **cannot modify the data every finding is derived from**,
which a shared writable volume would have permitted.

Semgrep's requirement is the one that would not have been guessed — it creates
`$HOME/.semgrep` on every run and dies with a bare `FileNotFoundError` when it
cannot. The adapter already carried a comment saying so, found the same way.

### 3. A separate image, not the worker's

The controller does not execute scanners and has no use for their data. Baking
3 GB into the image it runs would be waste, and it would keep scanner binaries
in the component holding the database credential.

So `deployments/docker/scanjob.Dockerfile` builds the scan job: the scanner
binaries, their provisioned data, and `cmd/scanjob`. The worker image is
unchanged — the in-process executor is still the default and still needs those
binaries.

### 4. What it costs, measured

| Data | On disk | Needed by |
|---|---|---|
| grype vulnerability database | 2.0 GB | every scan |
| trivy vulnerability database | 1.3 GB | image targets only |
| trivy checks bundle | 2.6 MB | every scan |
| semgrep rulesets | 1.6 MB | every scan |

**Measured after building it: 5.69 GB on disk, 0.81 GB on the wire** — for the
whole image, base layers included, against a worker image of 1.64 GB. The
vulnerability databases compress extremely well; trivy's is a 112 MB download
that expands to 1.3 GB, and grype's behaves similarly. An earlier estimate here
said roughly 1.2 GB of transfer, which was pessimistic and has been replaced
with the number rather than left standing.

So a node pulls 0.81 GB once and keeps 5.69 GB. That is the price of the
isolation, and the alternative was a storage requirement most clusters cannot
meet.

**The development cost is higher than the production one, and is worth stating
because it surprised the person who chose this.** In production the digest is
stable and the image is pulled once. While iterating, every deploy builds a new
digest, and the old ones stay on the node until something evicts them: a local
kind cluster reached 120 GB of 126 GB in roughly a dozen deploys, which took
PostgreSQL down with it and produced failures that looked nothing like a full
disk — scan pods dying with no logs at all.

Anyone iterating on this should prune between deploys. A `docker builder prune`
is not enough; the images accumulate inside the cluster's nodes.

That is a real cost and it is the price of the isolation. The alternative was a
storage requirement most clusters cannot meet.

### 5. Staleness must be visible, not implied

A baked database is only honest if its age can be seen. The image records its
build date, the scan records the data's age, and an age past a configured
threshold produces a **degradation** on that scanner's result — which makes the
scan PARTIAL and stops the gate passing it silently.

This is the control that makes §1's argument true rather than merely plausible.
Without it, a rebuild cadence that quietly lapses reproduces exactly the failure
ADR 012 refused.

## Verified

A repository scan on a kind cluster, in a pod with no database credential, no
queue credential, no service-account token and no route off the node:

```text
STATUS: COMPLETED   complete_coverage: True   commit: 9dd6af1f6d30fc79

  gitleaks  succeeded  deg=none  exit=0
  grype     succeeded  deg=none  exit=0
  semgrep   succeeded  deg=none  exit=0
  syft      succeeded  deg=none  exit=0
  trivy     succeeded  deg=none  exit=0
```

Five of five, no degradations. Before this decision the same scan produced two
of five and a PARTIAL the gate refused — which was the isolation working and the
product not.

## Alternatives considered

**A `ReadOnlyMany` volume and a provisioning job** — ADR 039 §6's original
answer. Rejected on availability: not offered by kind's default storage class
nor by default on most managed clusters, so the chart would fail where the
storage does not exist. It also introduces a refresh that must not corrupt
readers mid-scan, which needs versioned directories and an atomic swap.

**Bake only the small data, volume for the databases.** Semgrep's rules and
trivy's checks are 4 MB combined; the databases are 3.3 GB. This keeps the image
small and keeps the storage requirement, so it removes none of the blocker.

**An init container that fetches into the scan's own volume.** Requires egress
in the scan pod, which destroys the property the split exists for; and 3.3 GB
per scan is not workable regardless.

**Give the scan pod egress and provision at startup.** The single-Job design
whose network policy would then be identical to 12a's. That is 12b without its
best part, and this project already rejected it once.

## Consequences

**T-51 and `Capabilities.NetworkKinds` become deployable**, which is what has
kept them Partial while their controls were implemented and tested.

**A rebuild cadence becomes an operational obligation.** If it lapses, §5's
staleness degradation makes that visible in every scan rather than silent. The
cadence itself is a deployment concern this repository documents and does not
enforce.

**Image scanning needs the larger image.** A deployment that scans no images can
build without trivy's vulnerability database and save 1.3 GB; the Dockerfile
takes a build argument for this, and the default includes it, because an adapter
declaring `KindImage` that cannot serve it is worse than a large image.

**The worker image is unchanged**, so `make up` and the in-process default are
untouched.
