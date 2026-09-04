# ADR 030: ZAP ships in the worker image, invoked as a jar, with its add-ons trimmed

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

[ADR 026](026-dast-passive-only.md) landed the ZAP adapter and closed Phase 3b:
every target kind the model defines now has an adapter. It also recorded a gap
it did not close — **ZAP is not in the worker image**. ZAP is a Java
application, so packaging it is an infrastructure change of its own, and until
it lands an `endpoint` scan in a deployed worker degrades through the tested
"scanner binary missing" path.

That degradation is honest, and it is also the whole feature not working.
Submitted against the running stack today:

```json
"status": "failed",
"degraded_scanners": ["zap"],
"results": [{"scanner": "zap", "status": "skipped",
             "error": "scanner binary is not installed"}]
```

Nothing is mis-reported — no false pass, no invented finding — but SecureOps
cannot scan a running application, which is one of the eight domains §6 claims.

Everything below was **measured in a throwaway image**, not inferred. Where a
number appears, it came from a build and a run against a live target.

## Decision

### 1. ZAP ships inside the existing worker image

Not a sidecar, not a second worker pool.

The worker is already the only component that executes scanner binaries and
touches untrusted target content (§14.2). Putting ZAP anywhere else does not
shrink that boundary — it **moves** it, and every alternative moves it somewhere
worse:

- A **ZAP daemon container** driven over its REST API turns a subprocess the
  worker starts and kills into a long-lived HTTP service. ZAP's API is a
  proxy control plane; a reachable one is an open proxy with an authentication
  problem attached. It also rewrites the adapter from `exec` to an HTTP client,
  which is the one thing §7 rule 4 says adding a scanner must not require.
- A **separate `worker-dast` image** is the cleanest isolation and needs queue
  routing by target kind, which does not exist. That is Phase 12 work, and
  building it now to avoid 300 MB would be inventing scheduling infrastructure
  to solve a disk-space problem.
- **Docker-in-Docker**, spawning ZAP per scan, needs the Docker socket in the
  worker. The worker executes untrusted content. That is a container escape by
  design and is refused outright.

Cost, stated plainly and measured after the fact rather than estimated before
it: **187.4 MB of headless JRE and 114.8 MB of trimmed ZAP on the filesystem**,
and the image as `docker image ls` reports it goes from **1.09 GB to 1.58 GB**.
The reported figure grows by more than the files do — layer and package metadata
account for the rest — and both numbers are given because quoting only the
smaller one would be choosing the flattering measurement. It is a real cost, and
it is a cost rather than a risk.

### 2. It is invoked as `java -jar`, not through `zap.sh`

ZAP's launcher is `#!/usr/bin/env bash` and uses five bash-only constructs.
Alpine ships `ash`, not bash. Honouring the launcher would mean **adding bash to
the container that executes untrusted content** — a general-purpose shell, in
the one place §14 works hardest to keep spare.

Running the jar directly avoids that, and buys something as well. `zap.sh`
picks a heap size by inspecting available memory; invoking the jar sets `-Xmx`
explicitly, which turns a script's heuristic into a **declared resource limit**
of the kind §14.3 asks for.

Verified: `java -Xmx1024m -jar /opt/zap/zap-2.17.0.jar -cmd -dir … -silent
-autorun plan.yaml` ran the adapter's exact plan against a live target, spidered
it, passive-scanned it, and wrote the report. No bash in the image.

The adapter's environment allow-list already anticipates this — it sets no
`JAVA_HOME` and comments that "ZAP is a Java application and resolves JAVA_HOME
itself when unset". `/usr/bin` is on its `PATH`, and that is where Alpine's JRE
symlinks `java`.

### 3. Only the add-ons the plan uses are installed

ZAP's Crossplatform distribution ships 50 add-ons totalling 276 MB. The
automation plan needs nine of them, totalling 82.5 MB:

```
automation  commonlib  database  network  pscan  pscanrules  spider  reports  callhome
```

Two of those are not obvious and were found by running, not by reading.
`callhome` is a **mandatory** add-on — ZAP refuses to start without it, even
though the adapter disables its telemetry by config — and `commonlib` and
`database` are transitive dependencies that produce no error message naming
them.

The trimmed set was verified to produce **identical findings**: same alert
count, same plugin ids, against the same target.

This is the part that matters beyond disk space. The add-ons removed include
**`ascanrules`** — ZAP's active scan rules. ADR 026's control is that the
`activeScan` job is *absent from the plan rather than disabled in it*, so that
no configuration change can switch it on. Not shipping the rules at all is the
same argument carried one layer further down: there is now no configuration
*and* no code path that could run an active scan, because the payloads are not
in the image. `fuzz` and `spiderAjax` (which pulls in browser automation) go
with them.

### 4. The artifact is pinned and checksum-verified, following ADR 014

ZAP cannot be built from source with this project's toolchain, so
[ADR 009](009-build-scanners-from-source.md) does not transfer — the same
situation semgrep is in, and [ADR 014](014-semgrep-is-installed-not-built.md)
already settled the pattern: pin the version, verify the publisher's own
published digest before anything executes.

ZAP publishes SHA-256 digests for every release asset in its release notes.

```
ZAP_2.17.0_Crossplatform.zip
94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0
```

The Crossplatform archive is chosen over the Linux tarball deliberately: ZAP is
Java, the archive is architecture-independent, and **one digest covers both
`amd64` and `arm64`**. Semgrep needs a digest per architecture; this does not,
and fewer pins is fewer things to get wrong.

The JRE is Alpine's `openjdk21-jre-headless`, from the distribution's signed
package index, on the same footing as `git` and `python3` — the packages the
image already trusts. Headless matters: ZAP's GUI classes have no business in a
worker, and the adapter already sets `-Djava.awt.headless=true`.

## Alternatives considered

**Leave it as it is.** ZAP degrades honestly today, and honest degradation is
the correct behaviour for a missing scanner — not a substitute for having one.
This is the option that keeps `endpoint` a target kind nothing can serve.

**Bundle the JRE from ZAP's own distribution.** The `.dmg` and installer builds
embed a JRE. They are platform installers, not container artifacts, and taking a
JVM from an application vendor rather than from the distribution's package index
means it is patched on ZAP's release schedule, not Alpine's.

**Ship the full add-on set.** Simpler, 194 MB larger, and it puts active-scan
payloads into an image whose stated position is that it does not perform active
scans. Nine add-ons that were tested are better than fifty that were not.

**Use ZAP's official Docker image as the worker base.** It is Debian-based,
runs as `zap`, and carries a toolchain of its own. Adopting it would mean
rebuilding the worker's carefully pinned, built-from-source scanner set on
someone else's base — trading four ADRs' worth of supply-chain decisions for
convenience.

## Consequences

**What becomes possible.** `endpoint` targets run. The eighth scanner domain
stops being a claim the code cannot honour, and the "can I scan a website?"
question gets a yes — with ADR 026's limits, which do not change here.

The dashboard's URL bar gains the kind alongside it, because a target kind that
only the API can reach is only half-shipped. The kind is **chosen in the UI, not
inferred from the URL**: ".git means repository" and "github.com means
repository" both look reasonable and are wrong often enough that a heuristic
would clone a website or crawl a repository host, and the failure would read as
the platform being broken rather than the guess being wrong. The slug carries
the kind too, so a repository and its deployed site do not collapse into one
project and one risk score without either having been correlated to the other.

**What becomes harder.** The worker image is ~30% larger, so builds and pulls
are slower. A JVM is now in the image, which is a large runtime with its own
advisory stream; it enters the self-scan and the image scan like everything
else, and will produce findings that need triage.

**What is explicitly not changed.** DAST stays passive-only (ADR 026). Active
scanning still needs a per-project authorization model, and authenticated
scanning still needs credentials the worker does not hold. Egress for
`endpoint` targets is still declared through `Capabilities.NetworkKinds` and
still unenforced by anything — that remains Phase 12.

**What must be watched.** The add-on set is now a pinned list rather than
whatever the archive contains. If the plan gains a job, the list must gain its
add-on, and the failure mode is a startup error naming a missing add-on rather
than a silent skip — which is the right way round, and is how `callhome`,
`commonlib` and `database` were found. A test reads that list out of the
Dockerfile and fails both ways: when an add-on the plan needs is missing, and
when `ascanrules` reappears.

## Two things found while building it

Recorded because both look like the obviously correct thing to do, and both
break ZAP in ways whose error messages point somewhere else.

**`chmod -R a-w /opt/zap` breaks ZAP.** Making a verified installation read-only
is ordinary hardening. ZAP seeds a new home directory by *copying* `config.xml`
out of the install directory, and the copy inherits the source's mode — so a
read-only template produces a read-only `config.xml`, which ZAP then fails to
write, reporting "Permission denied" on a path under the *home* rather than
under `/opt`. It is also redundant: the installation is root-owned and every
scan runs as `nonroot`, so the worker already cannot write to it.

**A version probe needs `-dir`.** ZAP creates its home before it will print
anything, including its own version, and the adapter's environment allow-list
sets `HOME=/nonexistent` deliberately (§14.7). Without an explicit directory ZAP
throws on `/nonexistent/.ZAP` and prints a stack trace where the version should
be. The failure is silent where it matters: `Scan` ignores the version probe's
error by design, so this would have left every ZAP result carrying an empty
scanner version — a §7 rule 6 violation that nothing would have reported.
