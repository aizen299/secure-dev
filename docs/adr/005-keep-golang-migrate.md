# ADR 005: Keep golang-migrate despite unused-driver CVEs

- **Status:** Accepted
- **Date:** 2026-08-27

## Context

`golang-migrate` declares database drivers and test harnesses for engines
SecureOps does not use. Go records checksums for that whole module graph in
`go.sum`, so a scanner that resolves the graph through the Go toolchain reports
those modules as dependencies.

CI does exactly that: GitHub runners ship a Go toolchain, syft resolves the build
list through it (`metadataType: go-source-entry`), and the SBOM expands from 96
components to 111. Six CVEs surfaced, in `github.com/docker/docker` (pulled in by
the `dktest` Docker-based test harness) and its `go.opentelemetry.io/otel`
transitive.

None of that code ships:

```console
$ make build-go && go version -m bin/api bin/worker bin/migrate \
    | grep -cE 'docker/docker|opentelemetry'
0
```

The API links 11 modules, the worker 10, the migrate binary 2.

An earlier note in `.grype.yaml` called replacing golang-migrate "the root fix".
This ADR revisits that claim, because it does not survive scrutiny.

## Decision

**Keep `golang-migrate`.** Suppress the six CVEs in `.grype.yaml` with rules
scoped to specific vulnerability IDs, never to a package.

## Alternatives considered

**Replace it with an in-house migration runner (~80 lines).** This removes ~30
modules from the graph and eliminates the ignore file. Rejected: it trades a
*theoretical* supply-chain concern for a *real* correctness risk, in the one
component that mutates the schema, in a security product. A subtly wrong
migration runner — version tracking that races, a rollback that half-applies, a
dirty-state bug — is a worse outcome than checksum entries for code that is
never linked. `golang-migrate` is widely deployed and battle-tested; our
replacement would be neither.

**Suppress by package name.** Simpler and shorter, and wrong. It silences the
package forever, so a *future* CVE — including one in a driver we later start
using — disappears without anyone noticing. That is precisely how a real finding
gets missed (§15.12).

**Vendor only the drivers we use.** Go's module system does not support
partially vendoring a module's dependency graph. Not available.

**Lower the grype threshold to `critical`.** Rejected outright: weakening a gate
to make a build pass (§25.10).

## Consequences

- Six ignore rules in `.grype.yaml`, each with a justification and a stated
  re-review trigger.
- Because rules are ID-scoped, a **new** CVE in these modules still fails the
  build and forces this analysis to be redone. Verified by control test: removing
  one ID from the config makes that CVE fail again with exit 2.
- CI and local scan the same source tree but can catalogue it differently
  depending on whether a Go toolchain is present. The CI SBOM is uploaded as an
  artifact on every run, so any future divergence is inspectable rather than
  invisible.
- The ignore list is a debt signal. **Revisit this decision if it grows past a
  handful of entries, or if golang-migrate begins linking these drivers for
  real.** A long ignore list means the dependency is no longer paying for itself.
