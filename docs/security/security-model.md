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
| Correlated issues | The same, grouped and escalated — and they publish file paths findings do not |
| Threat intelligence | EPSS ranks findings by exploitation likelihood, turning an inventory into a prioritised plan |
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
2. **An unauthenticated network attacker.** Now stopped at the door: every
   endpoint under `/api/v1` except `/health` requires a bearer token
   ([ADR 006](../adr/006-interim-bearer-token-auth.md)).
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
default. Scanner binaries are built from source at pinned commits, gated by both
a container image scan and govulncheck (ADRs 009, 013).

**Authentication** — an interim static bearer token on every `/api/v1` endpoint
except `/health` ([ADR 006](../adr/006-interim-bearer-token-auth.md)). It
authenticates and does not authorize; Phase 11 replaces it. Landed in Phase 3a
rather than Phase 11 because `POST /scans` is a write endpoint and §15.4 requires
server-side authentication on every request.

**Secret redaction in findings** — required by §15.3 and now enforced by three
independent adapter controls: Gitleaks values are redacted before storage
(ADR 007), Trivy's quoted source lines are rewritten before anything is
persisted (ADR 015), and Semgrep results carrying matched source are refused
outright rather than filtered. Each is covered by a control test.

**Lifecycle honesty** — a finding is resolved only when every scanner that ever
reported it completed successfully and none saw it again. A degraded scan can
never read as "fixed" (T-37).

**Explainable correlation** — every link and issue membership carries readable
evidence, issues never chain transitively, and severity escalation never mutates
the findings it was derived from (T-41).

### Partial

**Least privilege** — containers run non-root with capabilities dropped and
read-only root filesystems. Per-role database users are not yet separated;
everything currently uses one role.

**Audit trail** — mutating requests are logged with the authenticated
principal's label, and `finding_status_history` records every lifecycle
transition with actor, reason, scan, and both states. There is still no
append-only `audit_logs` table and no before/after values for other entities
(T-24). The finding history exists ahead of it deliberately: a transition that
happens before the audit log lands is recorded nowhere and cannot be
reconstructed by re-scanning.

### Not implemented

**Authorization / RBAC.** The `Admin · Security Engineer · Developer · Viewer`
roles from §15.5 do not exist. There is no project scoping. Authentication
landed without it, so every valid token reaches every project (T-23).

**Audit logging** of security-sensitive actions (§15.6).

**Rate limiting.** No throttle on any endpoint, and the interim token cannot be
revoked short of a restart. Irrelevant while the stack binds to loopback;
blocking the moment it does not.

**Network policies** for scanner egress. Deny-by-default belongs with the
Kubernetes work in Phase 12; today a scanner subprocess has whatever egress the
container has.

## The gap that matters right now

**Authorization.** Authentication landed in Phase 3a and closed the previous
gap; authorization did not follow it, so every valid token is equivalent and
reaches every project (T-23).

What makes this the one to watch is that its impact grew through Phases 4-6
while the vulnerability itself stayed still. The API used to serve project names
and scan statuses. It now serves every project's full vulnerability inventory,
the file paths of correlated issues, and EPSS probabilities that rank those
findings by how likely they are to be exploited. The missing control has not
changed; what it fails to protect has (T-36, T-38).

The mitigating factor remains that nothing is deployed and the compose stack
binds to loopback. That is a deployment circumstance, not a control, and it
stops being true the moment anything is hosted.

## Review triggers

Update this document when a control moves between the three status sections,
when a new asset or adversary appears, or when a trust boundary changes (§21).
