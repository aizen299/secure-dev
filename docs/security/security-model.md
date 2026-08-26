# Security Model

SecureOps is a security product, so its own posture is part of the product
(spec §41, anti-pattern 10). This document states what SecureOps protects, who
it protects it from, and which controls are actually in place today versus
planned.

Status labels are used literally. **Implemented** means it exists and is tested.
**Partial** means some of it exists. **Not implemented** means none of it does —
never read an unqualified claim here as protection you have.

## Assets

| Asset | Why it matters |
|---|---|
| Scan findings | Reveal exactly where a customer's software is exploitable |
| Detected secrets | Live credentials; the single most damaging asset here |
| Raw scanner output | Contains findings and secret values verbatim |
| SBOMs | Full dependency inventory; useful for targeting |
| Security policies | Whoever edits these controls what gets blocked |
| Audit logs | The record of who changed what |
| Platform credentials | Database, Redis, registry, CI tokens |
| Scan targets | Customer source code held transiently in a workspace |

## Adversaries

1. **A malicious scan target.** The most important one. Anyone who can get
   SecureOps to scan a repository they control is executing scanner binaries
   against their own hostile content, inside our infrastructure.
2. **An unauthenticated network attacker.** Currently able to reach every
   endpoint — see the gap below.
3. **A low-privilege authenticated user** attempting to read another project's
   findings or relax a policy.
4. **A supply-chain attacker** targeting our dependencies, scanner binaries, or
   CI.
5. **A curious insider** reading findings or secrets they have no business
   seeing.

## Controls

### Implemented

**Scanner isolation** — the API never executes target content; execution is
confined to workers with argv-only invocation, ephemeral workspaces, resource
limits, and container hardening. See `trust-boundaries.md` §5 and
[ADR 004](../adr/004-scanner-isolation.md).

**Input validation** — allow-list based, on every target, at both the API and
the worker. Errors never echo attacker-supplied values, because errors are
logged.

**SSRF defence** — loopback, link-local, private, and cloud-metadata addresses
are refused at DNS resolution and again at dial time. Permitting private targets
is opt-in and **refused outright in production** (config validation fails at
boot).

**Secret handling** — credentials come from the environment, never source.
`Config` implements `slog.LogValuer` so logging the whole struct still redacts
DSNs. `.env` is gitignored, and `make scan-secrets` fails if that ever stops
being true.

**Resource limits** — per-scanner timeout, output cap that terminates the
process, job timeout, concurrency cap, workspace destruction. All configurable.

**Degraded-coverage honesty** — a scan where any scanner failed, was skipped, or
produced truncated output can never be recorded as `COMPLETED`. Partial evidence
must not produce a clean verdict.

**Supply chain** — dependencies scanned by grype and trivy; CI actions pinned to
immutable commit SHAs; SBOM generated and retained per run; `contents: read` by
default.

### Partial

**Least privilege** — containers run non-root with capabilities dropped and
read-only root filesystems. Per-role database users are not yet separated;
everything currently uses one role.

**Audit trail** — the schema records `created_at`/`updated_at` and scan
lifecycle timestamps. There is no `audit_logs` table and no actor attribution
yet, because there are no actors yet.

### Not implemented

**Authentication.** No mechanism of any kind. Every endpoint is reachable by
anyone who can reach the process.

**Authorization / RBAC.** The `Admin · Security Engineer · Developer · Viewer`
roles from §15.5 do not exist. There is no project scoping.

**Audit logging** of security-sensitive actions (§15.6).

**Secret redaction in findings.** Required by §15.3 — store a location and a
hash, never the secret value. Nothing produces findings yet, so nothing violates
this today, but it **must** land with the Gitleaks adapter, not after it.

**Network policies** for scanner egress. Deny-by-default belongs with the
Kubernetes work in Phase 12; today a scanner subprocess has whatever egress the
container has.

## The gap that matters right now

There is no authentication. The mitigating factor is that nothing is deployed
and the compose stack binds to loopback only. That is a deployment accident, not
a control.

Once write endpoints exist, an unauthenticated caller can make the platform
fetch URLs of their choosing — the SSRF policy bounds *where*, but not *whether*.
An interim shared-secret gate is therefore planned alongside the first write
endpoint, to be replaced by real authentication and RBAC in Phase 11.

## Review triggers

Update this document when a control moves between the three status sections,
when a new asset or adversary appears, or when a trust boundary changes (§21).
