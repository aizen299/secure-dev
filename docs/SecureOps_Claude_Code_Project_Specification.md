# SecureOps: Claude Code Project Specification & CLAUDE.md Generation Brief

## Purpose of This Document

This document is the consolidated project brief for **SecureOps**, a unified DevSecOps platform for automated security assessment.

Use this document as the authoritative input when invoking Claude Code to inspect the repository and create the project's root `CLAUDE.md`.

The goal is **not** for Claude Code to immediately implement the whole application. Claude Code should first understand the architecture, constraints, security model, development workflow, and intended feature set, then generate a high-quality `CLAUDE.md` that will govern future Claude Code sessions.

Claude Code must treat this document as the project direction and source of truth unless a later, explicit architectural decision supersedes it.

---

# 1. Project Identity

## Project Name

**SecureOps**

## Recommended GitHub Repository

```text
secureops
```

Fallback names if unavailable:

```text
secureops-devsecops
secureops-platform
secureops-security-platform
secureops-scanner
secureops-devsecops-platform
```

Preferred repository name remains:

```text
secureops
```

## GitHub Description

> Unified DevSecOps platform for automated source code, dependency, container, secret, API, and infrastructure security assessment with vulnerability correlation, unified risk scoring, and prioritized remediation.

## License

The repository already contains an **MIT License**.

Do not remove or replace the MIT license without explicit instruction.

---

# 2. Project Abstract

SecureOps is a unified DevSecOps platform that automates comprehensive security assessment throughout the software development lifecycle.

The platform performs source code, dependency, container image, secrets, infrastructure configuration, SBOM, and API security analysis through a single integrated interface by orchestrating multiple industry-standard security tools.

It correlates findings from different security scanners, eliminates duplicate vulnerabilities, computes a unified and contextual project risk score, and generates prioritized remediation recommendations through a centralized dashboard.

By providing contextual security insights, security gates, historical trends, and actionable reports, SecureOps enables developers and security teams to identify, prioritize, and mitigate security risks before software deployment, thereby strengthening overall software supply-chain security.

---

# 3. Core Objectives

SecureOps should:

1. Design and develop a unified DevSecOps platform for automated security assessment.
2. Analyze source code for security vulnerabilities.
3. Detect exposed secrets and credentials.
4. Generate and manage Software Bills of Materials (SBOMs).
5. Analyze dependencies for known vulnerabilities.
6. Analyze container images for vulnerabilities and configuration issues.
7. Analyze infrastructure-as-code and security configuration.
8. Analyze APIs through dynamic/API security testing.
9. Normalize heterogeneous scanner results into a canonical finding model.
10. Correlate related findings across multiple security domains.
11. Eliminate duplicate or overlapping vulnerability alerts.
12. Compute a unified contextual project security/risk score.
13. Generate prioritized remediation recommendations.
14. Provide configurable security policies and CI/CD gates.
15. Integrate with GitHub Actions for continuous security assessment.
16. Provide a centralized dashboard for findings, trends, risk metrics, assets, SBOMs, and remediation status.
17. Maintain historical scan data and vulnerability lifecycle information.
18. Isolate security scanner execution from the main API service.
19. Provide authentication, authorization, auditability, and secure handling of secrets.
20. Make the platform itself secure enough to credibly serve as a DevSecOps/security project.

---

# 4. Core Innovation

The project should not be presented as merely a dashboard that runs multiple CLI tools.

The central innovation is the pipeline:

```text
SCAN
  ↓
NORMALIZE
  ↓
CORRELATE
  ↓
CONTEXTUALIZE
  ↓
SCORE RISK
  ↓
REMEDIATE
  ↓
SECURITY GATE
  ↓
REPORT
```

The primary innovation components are:

## 4.1 Security Finding Normalization Engine

Different security scanners produce different output formats and finding models.

SecureOps should transform scanner-specific output into a canonical SecureOps finding model.

```text
Gitleaks JSON ─────┐
Semgrep JSON ──────┤
Syft output ───────┤
Grype JSON ────────┤
Trivy JSON ────────┤──> Normalization ──> SecureOps Finding
ZAP output ────────┘
```

The rest of the application should operate on normalized findings rather than scanner-specific formats.

## 4.2 Cross-Domain Vulnerability Correlation

Correlate findings from:

- SAST
- secrets
- dependencies
- SBOM
- containers
- IaC/configuration
- APIs

The system should identify when multiple scanner findings represent the same underlying security problem or related risks.

Example:

```text
Grype:
CVE-XXXX
package: express
severity: HIGH

+

Semgrep:
unsafe Express configuration
file: server.ts
line: 82

+

Trivy:
vulnerable package inside production container

↓

SecureOps Correlation

ONE contextual security issue

"Vulnerable Express dependency is deployed inside a production
container and is used by an affected application component."

Risk: CRITICAL
```

## 4.3 Context-Aware Unified Risk Scoring Engine

The risk engine should not simply map:

```text
Critical = 10
High = 7
Medium = 4
Low = 1
```

The model should be formalized and documented.

Potential factors:

- CVSS severity
- exploitability
- asset criticality
- exposure
- reachability
- vulnerability density
- confidence
- affected component count
- production/development context
- internet exposure
- presence of known exploits
- whether a vulnerable component is actually deployed
- whether a vulnerable dependency is reachable by an API or application path

A conceptual model:

```text
Risk =
    Severity Weight
    × Exploitability
    × Exposure
    × Asset Criticality
    × Confidence
```

Normalize the final project score to:

```text
0 ───────────────────── 100
Secure                  Critical
```

Example dashboard:

```text
SECURITY SCORE

72 / 100

HIGH RISK

Critical     3
High         12
Medium       27
Low          41

Risk trend   ↓ 18%
```

The exact formula should be implemented as a deterministic, testable component and documented in an ADR or design document.

## 4.4 Intelligent Remediation Engine

The remediation system should:

- consolidate recommendations from multiple scanners
- deduplicate recommendations
- prioritize remediation
- identify the affected component
- provide deterministic remediation information where available
- distinguish verified remediation from AI-generated contextual explanation
- avoid inventing fixes

Example:

```text
CVE-XXXX
↓
Affected package: lodash
↓
Current version: affected version
↓
Fixed version: supported fixed version
↓
Recommended:
Update dependency and regenerate lockfile.
```

AI assistance may improve explanation and prioritization, but deterministic scanner/vendor data should remain authoritative.

## 4.5 Security Policy Engine

SecureOps should support configurable security gates.

Example:

```text
FAIL if:

Critical findings > 0

OR

High findings > 5

OR

Secrets detected > 0

OR

Risk score < 70
```

Example result:

```text
SECURITY GATE

Result: FAILED

Reason:
3 CRITICAL vulnerabilities
2 exposed secrets
Risk Score: 41/100

Deployment blocked.
```

Or:

```text
SECURITY GATE

Result: PASSED

Critical: 0
High: 1
Risk Score: 91/100
```

## 4.6 Centralized Security Dashboard

The dashboard should provide:

- project overview
- current security score
- severity distribution
- findings
- scan history
- risk trends
- vulnerability trends
- remediation status
- assets
- dependencies
- containers
- APIs
- SBOM information
- security gate results
- scanner status
- historical comparisons

---

# 5. Recommended Technology Stack

## Frontend

```text
Next.js
TypeScript
Tailwind CSS
shadcn/ui
Recharts
```

## Backend

```text
Go
Chi or Gin
```

Preferred direction:

```text
Go + Chi
```

The backend should own:

- REST/API layer
- authentication/authorization
- scan orchestration
- scanner lifecycle
- job management
- persistence
- normalization
- correlation
- risk scoring
- remediation
- policy evaluation
- reporting

Do not introduce Python merely because security tooling often uses Python.

Python can be introduced later only when there is a real technical reason, such as specialized ML/data-analysis functionality.

## Database

```text
PostgreSQL
```

PostgreSQL is preferred because the application's core entities and relationships are strongly relational.

## Queue / Cache

```text
Redis
```

Redis should support asynchronous scanner jobs, transient state, and appropriate caching.

## Security Tools

### SAST

```text
Semgrep
```

### Secrets

```text
Gitleaks
```

### SBOM

```text
Syft
```

### Dependency Vulnerabilities

```text
Grype
```

### Container / Repository / IaC / Configuration Security

```text
Trivy
```

### API / DAST

```text
OWASP ZAP
```

## Containerization

```text
Docker
```

## Orchestration

```text
Kubernetes
Helm
```

Kubernetes should be used meaningfully rather than included merely as a technology keyword.

## CI/CD

```text
GitHub Actions
```

## Observability

Potential stack:

```text
OpenTelemetry
Prometheus
Grafana
```

Keep observability proportional to the project. Basic metrics, structured logs, traces, and health checks are more important than building an entire observability platform.

---

# 6. Scanner Responsibility Matrix

| Security Domain | Tool | Responsibility |
|---|---|---|
| SAST | Semgrep | Source-code vulnerabilities |
| Secrets | Gitleaks | Exposed credentials/secrets |
| SBOM | Syft | Software Bill of Materials |
| Dependency | Grype | Known dependency vulnerabilities |
| Container | Trivy | Container/image vulnerabilities |
| Repository | Trivy | Repository vulnerabilities/configuration/secrets where applicable |
| IaC | Trivy | Infrastructure/configuration misconfiguration |
| API/DAST | OWASP ZAP | Dynamic application/API security testing |
| License | Trivy / SBOM ecosystem | License/component visibility |

Do not blindly duplicate scanners.

Every scanner should have a clearly defined responsibility.

---

# 7. High-Level Architecture

The intended architecture is:

```text
                         ┌──────────────┐
                         │   Developer  │
                         └──────┬───────┘
                                │
                       Push / Pull Request
                                │
                                ▼
                       ┌─────────────────┐
                       │ GitHub Actions  │
                       └────────┬────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────┐
│                    SECUREOPS PLATFORM                   │
│                                                         │
│  ┌──────────────┐                                       │
│  │ Go API       │                                       │
│  └──────┬───────┘                                       │
│         ▼                                               │
│  ┌──────────────┐                                       │
│  │ Job Queue    │                                       │
│  │ Redis        │                                       │
│  └──────┬───────┘                                       │
│         ▼                                               │
│  ┌─────────────────────────────────────────────┐        │
│  │              Scanner Workers               │        │
│  │                                             │        │
│  │ Semgrep Gitleaks Syft Grype Trivy ZAP     │        │
│  └────────────────────┬────────────────────────┘        │
│                       ▼                                 │
│              ┌──────────────────┐                       │
│              │ Normalization    │                       │
│              └────────┬─────────┘                       │
│                       ▼                                 │
│              ┌──────────────────┐                       │
│              │ Correlation      │                       │
│              └────────┬─────────┘                       │
│                       ▼                                 │
│              ┌──────────────────┐                       │
│              │ Risk Engine      │                       │
│              └────────┬─────────┘                       │
│                       ▼                                 │
│              ┌──────────────────┐                       │
│              │ Remediation      │                       │
│              └────────┬─────────┘                       │
│                       ▼                                 │
│              ┌──────────────────┐                       │
│              │ Policy Engine    │                       │
│              └────────┬─────────┘                       │
│                       ▼                                 │
│              PASS / FAIL / WARN                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
                       │
                       ▼
                ┌───────────────┐
                │ Next.js       │
                │ Dashboard     │
                └───────────────┘
```

A more detailed backend architecture:

```text
                         ┌──────────────────────┐
                         │      Next.js UI      │
                         │ TypeScript + Tailwind│
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Go API / Backend   │
                         │      Orchestrator    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      Redis Queue     │
                         └──────────┬───────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             ▼                      ▼                      ▼
       Source Worker          Dependency Worker      Container Worker
             │                      │                      │
          Semgrep              Syft / Grype              Trivy
          Gitleaks
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                            Normalization Layer
                                    │
                                    ▼
                            Correlation Engine
                                    │
                                    ▼
                             Risk Engine
                                    │
                                    ▼
                          Remediation Engine
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                    PostgreSQL            Report Engine
```

---

# 8. Core Scan Pipeline

Every scan should conceptually follow:

```text
Target
  ↓
Target Validation
  ↓
Scanner Selection
  ↓
Asynchronous Job Creation
  ↓
Scanner Execution
  ↓
Raw Results
  ↓
Parsing
  ↓
Normalization
  ↓
Deduplication
  ↓
Cross-Domain Correlation
  ↓
Context Enrichment
  ↓
Risk Scoring
  ↓
Remediation Generation
  ↓
Policy Evaluation
  ↓
Persistence
  ↓
Report / Dashboard / CI Result
```

---

# 9. Scanner Abstraction

The backend should expose a stable internal scanner interface.

Conceptual Go interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, target Target) (RawResult, error)
}
```

Each scanner should be implemented as an adapter.

Suggested structure:

```text
internal/scanners/
├── gitleaks/
│   ├── scanner.go
│   ├── parser.go
│   └── mapper.go
│
├── semgrep/
│   ├── scanner.go
│   ├── parser.go
│   └── mapper.go
│
├── syft/
│   ├── scanner.go
│   ├── parser.go
│   └── mapper.go
│
├── grype/
│   ├── scanner.go
│   ├── parser.go
│   └── mapper.go
│
├── trivy/
│   ├── scanner.go
│   ├── parser.go
│   └── mapper.go
│
└── zap/
    ├── scanner.go
    ├── parser.go
    └── mapper.go
```

The core platform should never depend directly on scanner-specific result formats.

---

# 10. Canonical Finding Model

Every scanner result should eventually map into a SecureOps finding.

Conceptual model:

```text
Finding
├── id
├── scanner
├── scanner_finding_id
├── category
├── severity
├── title
├── description
├── file
├── line
├── package
├── dependency
├── container
├── image
├── endpoint
├── cve
├── cwe
├── cvss
├── exploitability
├── evidence
├── remediation
├── fingerprint
├── confidence
├── asset_id
├── project_id
├── scan_id
├── first_seen
├── last_seen
└── status
```

This is conceptual. The final schema should be refined during implementation.

---

# 11. Vulnerability Fingerprinting and Deduplication

Do not deduplicate findings merely using title equality.

A fingerprint should consider stable identifying information.

Conceptual approach:

```text
fingerprint =
SHA256(
    vulnerability_type +
    normalized_location +
    package +
    CVE/CWE +
    affected_component
)
```

The exact fingerprint strategy should be documented and covered by tests.

The system should distinguish:

- exact duplicates
- likely duplicates
- related findings
- independent findings

Do not merge findings merely because they look similar.

---

# 12. Asset Inventory

SecureOps should maintain an understanding of the software assets associated with a project.

Conceptual model:

```text
Project
 ├── Repository
 ├── Branch
 ├── Commit
 ├── Services
 ├── Dependencies
 ├── Containers
 ├── APIs
 ├── Secrets
 ├── SBOM
 └── Findings
```

This asset inventory should support contextual risk calculation.

---

# 13. Scan Lifecycle

A scan should be a durable entity.

Conceptual model:

```text
Scan
├── ID
├── project
├── commit SHA
├── branch
├── started_at
├── completed_at
├── status
├── scanner versions
└── result summary
```

Suggested states:

```text
QUEUED
RUNNING
PARTIAL
COMPLETED
FAILED
CANCELLED
```

Scanner failures should be represented clearly.

A partial scanner failure should not silently become a successful complete scan.

---

# 14. Asynchronous Scanning

Do not make the API request wait for every scanner.

Preferred flow:

```text
POST /scans
     ↓
   202
     ↓
scan_id
```

Then:

```text
API
 │
 ▼
Redis Queue
 │
 ├── Semgrep Worker
 ├── Gitleaks Worker
 ├── Syft Worker
 ├── Grype Worker
 ├── Trivy Worker
 └── ZAP Worker
```

Scanner jobs should support:

- cancellation
- timeout
- retries where safe
- concurrency limits
- resource limits
- progress/status reporting
- structured failure reporting

---

# 15. PostgreSQL Data Model

At minimum, expect entities conceptually similar to:

```text
users
projects
repositories
scans
findings
finding_occurrences
assets
dependencies
containers
apis
sboms
remediations
security_policies
policy_results
scan_metrics
audit_logs
```

The final relational model should be designed deliberately.

Avoid introducing a document database simply for convenience.

---

# 16. Security Model

SecureOps itself must be secure.

Required concepts:

## Authentication

Use a secure authentication mechanism appropriate to the deployment.

## Authorization

Implement RBAC.

Suggested roles:

```text
Admin
Security Engineer
Developer
Viewer
```

## Secrets

Never:

- hard-code credentials
- commit `.env` files
- log secrets
- store credentials as plaintext unnecessarily

## Auditability

Track security-sensitive actions such as:

- scan creation
- project changes
- policy changes
- finding state changes
- user/role changes
- remediation actions

---

# 17. Scanner Isolation

This is a critical architectural requirement.

SecureOps may process attacker-controlled repositories, Dockerfiles, package manifests, archives, and other untrusted artifacts.

Never blindly execute untrusted repository code on the main API server.

Scanner execution should occur in isolated workers.

At minimum, use:

```text
Scanner Worker
    │
    ├── restricted filesystem
    ├── non-root user
    ├── CPU limit
    ├── memory limit
    ├── execution timeout
    ├── network restrictions
    └── ephemeral workspace
```

Potentially use Kubernetes Jobs or another isolated execution mechanism for stronger separation.

The scanner should not need broad privileges.

---

# 18. Resource Exhaustion Protection

Untrusted repositories may contain:

- extremely large files
- enormous repositories
- millions of files
- pathological archives
- massive dependency trees
- malicious build/configuration content
- unusually large scanner outputs

Scanner workers should enforce:

```text
maximum repository size
maximum scan duration
maximum memory
maximum CPU
maximum output size
maximum concurrent scans
maximum artifact size
```

These limits should be configurable.

---

# 19. Threat Model

Create and maintain:

```text
docs/security/threat-model.md
```

Important trust boundaries:

```text
User
 ↓
Web UI
 ↓
API
 ↓
Orchestrator
 ↓
Scanner Worker
 ↓
Untrusted Repository
```

Threats to consider include:

- malicious repository
- malicious Dockerfile
- malicious package
- command injection
- path traversal
- SSRF
- container escape
- secret leakage
- resource exhaustion
- poisoned scanner output
- compromised CI token
- malicious uploaded SBOM
- insecure webhook
- privilege escalation
- insecure artifact handling
- scanner binary tampering
- dependency supply-chain compromise

The threat model should be updated when architecture changes materially.

---

# 20. CI/CD Integration

GitHub Actions should be a first-class integration.

Preferred pipeline:

```text
Pull Request / Push
        ↓
GitHub Actions
        ↓
SecureOps Scan
        ↓
Normalization
        ↓
Correlation
        ↓
Risk Evaluation
        ↓
Policy Engine
        ↓
PASS / FAIL / WARN
```

The CI integration should expose machine-readable output and a clear human-readable summary.

Example:

```text
SecureOps Security Gate

Result: FAILED

Critical: 3
High: 7
Secrets: 2
Risk Score: 41/100

Deployment blocked.
```

---

# 21. GitHub Actions Security

CI itself is part of the attack surface.

Use least-privilege permissions.

Conceptually:

```yaml
permissions:
  contents: read
```

Grant additional permissions only where necessary.

Where practical, pin third-party GitHub Actions to immutable commit SHAs rather than relying solely on mutable tags.

Never expose sensitive credentials unnecessarily to pull-request workflows.

---

# 22. SBOM as a First-Class Feature

Do not merely generate an SBOM and discard it.

The dashboard should expose:

```text
SBOM

Components       347
Direct            42
Transitive        305

Vulnerable         17
Critical            2

Licenses
MIT                201
Apache-2.0          72
GPL                 11
Unknown              3
```

Potential supported formats:

```text
CycloneDX
SPDX
```

SBOMs should be associated with:

- project
- repository
- commit
- scan
- generated timestamp
- tool/version

---

# 23. Vulnerability Lifecycle

Findings should support a lifecycle rather than only OPEN/CLOSED.

Suggested states:

```text
OPEN
ACKNOWLEDGED
IN_PROGRESS
RESOLVED
REOPENED
FALSE_POSITIVE
IGNORED
```

For state changes, store:

```text
who changed it
when
why
previous state
new state
```

This supports auditability and historical analysis.

---

# 24. Historical Security Analytics

The dashboard should track security trends over time.

Useful metrics:

- overall risk score
- critical vulnerabilities
- high vulnerabilities
- medium vulnerabilities
- low vulnerabilities
- exposed secrets
- dependency vulnerabilities
- container vulnerabilities
- API findings
- remediation rate
- mean time to remediation
- security gate pass/fail rate

Conceptual chart:

```text
Risk Score

100 ┤
 90 ┤       ╭───╮
 80 ┤   ╭───╯   ╰──
 70 ┤───╯
 60 ┤
    └────────────────
       commits/time
```

---

# 25. Security Policy Engine

Policies should eventually be configurable per project.

Example policy:

```text
Critical findings:
    maximum = 0

High findings:
    maximum = 5

Secrets:
    maximum = 0

Minimum risk score:
    70
```

The engine should produce:

```text
PASS
WARN
FAIL
```

and explain the exact policy conditions that caused the result.

---

# 26. Kubernetes Strategy

Do not add Kubernetes merely as a résumé keyword.

Use Kubernetes for real workloads.

Potential architecture:

```text
Kubernetes Cluster
│
├── secureops-web
├── secureops-api
├── secureops-worker
├── secureops-scanner-jobs
├── redis
└── postgres
```

Scanner jobs can potentially be ephemeral Kubernetes Jobs with:

- resource requests/limits
- security contexts
- non-root execution
- restricted capabilities
- network policy
- ephemeral volumes
- timeouts
- cleanup after completion

Use Helm if it simplifies repeatable deployment.

Do not over-engineer Kubernetes before the application architecture works locally.

---

# 27. Recommended Repository Structure

Target structure:

```text
secureops/
│
├── apps/
│   └── web/
│
├── cmd/
│   ├── api/
│   ├── worker/
│   └── cli/
│
├── internal/
│   ├── auth/
│   ├── projects/
│   ├── scans/
│   ├── scanners/
│   │   ├── gitleaks/
│   │   ├── semgrep/
│   │   ├── syft/
│   │   ├── grype/
│   │   ├── trivy/
│   │   └── zap/
│   │
│   ├── normalization/
│   ├── correlation/
│   ├── risk/
│   ├── remediation/
│   ├── policies/
│   ├── assets/
│   ├── sbom/
│   └── reports/
│
├── migrations/
│
├── deployments/
│   ├── docker/
│   └── kubernetes/
│
├── .github/
│   └── workflows/
│
├── docs/
│   ├── architecture/
│   ├── security/
│   ├── adr/
│   └── api/
│
├── scripts/
│
├── tests/
│   ├── integration/
│   └── fixtures/
│
├── .claude/
│   ├── settings.json
│   └── commands/
│       ├── test.md
│       ├── security-audit.md
│       ├── architecture-review.md
│       └── scan.md
│
├── CLAUDE.md
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── LICENSE
└── README.md
```

Do not create every directory immediately if it has no purpose. Build toward this structure as features are implemented.

---

# 28. Documentation Structure

Maintain architectural documentation separately from source code.

Suggested structure:

```text
docs/
├── architecture/
│   ├── overview.md
│   ├── scanner-pipeline.md
│   ├── correlation.md
│   └── risk-engine.md
│
├── adr/
│   ├── 001-go-backend.md
│   ├── 002-postgresql.md
│   ├── 003-redis.md
│   └── 004-scanner-isolation.md
│
├── security/
│   ├── threat-model.md
│   ├── security-model.md
│   └── trust-boundaries.md
│
└── api/
    └── openapi.yaml
```

Use Architecture Decision Records for meaningful architecture changes.

---

# 29. Claude Code Role

Claude Code should be treated as a **senior implementation agent operating under explicit architecture and security constraints**.

Claude Code should help with:

- implementation
- scaffolding
- refactoring
- testing
- debugging
- documentation
- integration
- code review
- architecture validation
- security review

Claude Code should NOT autonomously redefine the architecture without documenting the reason and obtaining approval where the change is material.

The human/project owner decides:

- architecture
- security model
- threat model
- data model
- major technology choices
- requirements
- acceptance criteria

Claude Code accelerates implementation and analysis.

---

# 30. Root CLAUDE.md Requirements

Claude Code must create a root:

```text
CLAUDE.md
```

The generated `CLAUDE.md` should contain at least:

1. Project purpose
2. Architecture overview
3. Technology stack
4. Repository structure
5. Core scan pipeline
6. Scanner responsibilities
7. Scanner abstraction
8. Canonical finding model
9. Correlation rules
10. Risk engine rules
11. Remediation rules
12. Security policy engine
13. Database conventions
14. API conventions
15. Frontend conventions
16. Testing requirements
17. Security requirements
18. Scanner isolation rules
19. Git/commit rules
20. Documentation rules
21. Definition of Done
22. Things Claude must never do
23. Development workflow
24. Validation commands
25. Architecture-change procedure

The file should be concise enough to be useful but detailed enough to prevent architectural drift.

---

# 31. Proposed CLAUDE.md Core Rules

Claude Code should generate rules equivalent to the following:

```text
# SecureOps

SecureOps is a unified DevSecOps security assessment platform.

## Architecture

Frontend:
Next.js + TypeScript + Tailwind CSS

Backend:
Go

Database:
PostgreSQL

Queue:
Redis

Security engines:
Semgrep
Gitleaks
Syft
Grype
Trivy
OWASP ZAP

Core pipeline:

Repository / Target
→ Scanner Orchestration
→ Raw Results
→ Normalization
→ Correlation
→ Context Enrichment
→ Risk Scoring
→ Remediation
→ Security Policy
→ Dashboard / Report / CI Gate

## Mandatory Security Rules

1. Never store secrets in source code.
2. Never commit .env files or credentials.
3. Never execute untrusted repository code on the API server.
4. Scanner execution must be isolated.
5. Use resource limits and timeouts for scanner jobs.
6. All scanner output must pass through a normalization layer.
7. Never couple the UI directly to scanner-specific output.
8. Security-sensitive actions must be auditable.
9. Authentication and authorization must be enforced server-side.
10. Never trust scanner output blindly.
11. Treat repository contents, SBOMs, archives, and scanner output as potentially malicious input.
12. Validate all external input.
13. Do not introduce insecure shell execution.
14. Avoid running containers as root.
15. Follow least privilege.
16. Do not disable security controls simply to make tests pass.

## Engineering Rules

1. Inspect the repository before modifying it.
2. Prefer small, coherent changes.
3. Do not modify unrelated files.
4. Do not introduce dependencies without a clear reason.
5. Preserve existing functionality.
6. Write tests for new behavior.
7. Run formatting, linting, and tests after implementation.
8. Review the final git diff.
9. Document significant architecture decisions.
10. Do not silently change public APIs.

## Scanner Rules

Each scanner must implement the shared scanner abstraction.

Scanner-specific output must be parsed by its adapter.

The rest of the platform consumes normalized findings.

Never spread scanner-specific conditionals throughout the codebase.

## Definition of Done

A feature is complete only when:

- implementation exists
- unit tests pass
- integration tests pass where applicable
- linting passes
- formatting passes
- security checks pass
- documentation is updated where required
- no unintended git changes remain
- behavior is verified against acceptance criteria
```

Claude Code should refine these rules rather than blindly copy them.

---

# 32. Claude Code Development Workflow

Use this workflow:

```text
1. Requirement
      ↓
2. Inspect repository
      ↓
3. Identify affected architecture
      ↓
4. Produce implementation plan
      ↓
5. Human reviews plan
      ↓
6. Implement only approved scope
      ↓
7. Run tests
      ↓
8. Run linting/formatting
      ↓
9. Run security checks
      ↓
10. Inspect git diff
      ↓
11. Report changes and risks
      ↓
12. Commit only when explicitly instructed
```

Claude Code should not assume that a feature request means "rewrite the architecture."

---

# 33. Claude Code Initial Repository Reconnaissance

The first Claude Code instruction after this document should be approximately:

```text
Read the project specification provided in this document and inspect the entire repository.

Do not modify any files.

Analyze:

1. Current repository state
2. Existing architecture
3. Existing files and technologies
4. Missing components
5. Proposed directory structure
6. Database entities
7. Scanner abstraction
8. API boundaries
9. Security trust boundaries
10. Threat model
11. Testing strategy
12. CI/CD requirements
13. Claude Code project rules
14. Recommended implementation phases

Then produce a concise implementation plan and identify any contradictions between the current repository and this specification.

Do not implement anything yet.
```

After reviewing the plan, implementation can proceed phase by phase.

---

# 34. Phase-Based Implementation Strategy

Do not attempt to build the whole system in one request.

## Phase 1: Foundation

Build:

```text
Repository structure
Go API
Next.js app
PostgreSQL
Redis
Docker Compose
configuration
logging
health checks
basic CI
```

## Phase 2: Scanner Abstraction

Build:

```text
Scanner interface
Target model
Scan job model
Scanner lifecycle
Worker infrastructure
```

## Phase 3: Initial Scanner Adapters

Implement:

```text
Gitleaks
Semgrep
Syft
Grype
Trivy
ZAP
```

One scanner at a time.

## Phase 4: Normalization

Implement:

```text
Raw result storage
Scanner parsers
Canonical Finding model
Validation
Fingerprinting
Deduplication
```

## Phase 5: Correlation

Implement:

```text
cross-domain relationships
related findings
duplicate handling
component relationships
asset relationships
```

## Phase 6: Risk Engine

Implement:

```text
severity
CVSS
exploitability
exposure
asset criticality
confidence
reachability
deployment context
risk score
```

Include unit tests for the scoring formula.

## Phase 7: Remediation

Implement:

```text
remediation mapping
recommendation aggregation
priority
fix metadata
status tracking
```

## Phase 8: Security Policy Engine

Implement:

```text
policy configuration
PASS/WARN/FAIL
CI result
security gates
```

## Phase 9: Dashboard

Implement:

```text
project dashboard
scan history
findings
finding details
risk score
trends
assets
SBOM
remediation
security gate results
```

## Phase 10: CI/CD

Implement:

```text
GitHub Actions integration
PR reporting
status checks
machine-readable results
security gates
```

## Phase 11: Security Hardening

Implement:

```text
authentication
RBAC
audit logging
scanner isolation
resource limits
network restrictions
secure secret handling
input validation
```

## Phase 12: Kubernetes

Implement:

```text
Docker images
Kubernetes deployments
scanner jobs
resource limits
security contexts
network policies
Helm
```

## Phase 13: Observability — dropped 2026-09-05

Implement only what is justified:

```text
structured logging
metrics
health checks
tracing where useful
```

> **This phase was removed from the plan on 2026-09-05.** Its own instruction —
> "implement only what is justified" — is what removed it: structured logging,
> health checks and per-scan telemetry had already shipped in Phases 1 and 2,
> and what remained was a metrics endpoint and tracing that answer no question a
> single-operator tool raises. See
> [ADR 034](adr/034-no-observability-phase.md) for the reasoning, the
> alternatives, and what would reverse it.
>
> The section is kept rather than deleted so the record shows what was planned
> as well as what was built.

## Phase 14: Final Hardening and Documentation

Complete:

```text
threat model
architecture documentation
ADRs
OpenAPI
README
deployment documentation
testing
security review
```

---

# 35. Testing Strategy

Testing must be treated as a first-class project requirement.

## Unit Tests

Cover:

- finding normalization
- fingerprinting
- deduplication
- correlation
- risk calculation
- remediation prioritization
- policy evaluation
- validation

## Integration Tests

Cover:

- API → database
- API → queue
- worker → scanner
- worker → normalization
- normalization → persistence
- policy → CI result

## Scanner Fixtures

Do not depend entirely on live scanner execution for tests.

Maintain fixtures representing realistic scanner outputs.

Example:

```text
tests/fixtures/
├── gitleaks/
├── semgrep/
├── syft/
├── grype/
├── trivy/
└── zap/
```

## End-to-End Tests

At least one complete path should exist:

```text
Test repository
    ↓
SecureOps scan
    ↓
scanner workers
    ↓
normalized findings
    ↓
correlation
    ↓
risk score
    ↓
policy
    ↓
dashboard/API result
```

---

# 36. Quality Gates

Before declaring work complete, Claude Code should run the relevant:

```text
format
lint
unit tests
integration tests
security scans
build
```

The exact commands should be discovered from the repository rather than invented.

Claude Code should report:

```text
Changed files
Tests run
Tests passed/failed
Lint status
Security scan status
Build status
Known limitations
Potential regressions
```

---

# 37. Git Workflow

The repository already has an MIT license.

Claude Code should:

- preserve the license
- avoid unrelated changes
- avoid force-pushing
- avoid rewriting git history
- never delete user work without explicit approval
- never commit secrets
- never commit generated artifacts unnecessarily
- inspect `git status`
- inspect `git diff`
- commit only when explicitly instructed

Suggested commit style:

```text
feat(scanner): add gitleaks adapter
feat(risk): implement contextual risk scoring
feat(policy): add security gate evaluation
fix(correlation): prevent duplicate findings
test(normalization): add trivy fixtures
docs(architecture): document scanner pipeline
```

---

# 38. Claude Code Permission Philosophy


Use explicit permissions and review sensitive operations.

High-risk operations include:

- deleting files
- changing infrastructure
- changing security policies
- modifying CI permissions
- modifying Kubernetes privileges
- executing untrusted code
- changing authentication
- changing database migrations
- installing large or security-sensitive dependencies

---

# 39. MCP Strategy

MCP is optional tooling for Claude Code and must not become a runtime dependency of SecureOps.

Potential useful MCP integrations:

### GitHub MCP

Useful for:

- repository metadata
- issues
- pull requests
- commits
- branches

### Playwright MCP

Useful later for:

- browser testing
- dashboard validation
- end-to-end UI tests

### Documentation tools

Useful for current framework/library documentation when necessary.

Important principle:

```text
SecureOps must function without Claude Code.
SecureOps must function without MCP.
```

MCP exists to improve Claude Code's development workflow, not to become part of the application's production architecture.

---

# 40. Architecture Decision Records

Create ADRs for meaningful architectural decisions.

Initial candidates:

```text
001-go-backend.md
002-postgresql.md
003-redis.md
004-scanner-isolation.md
005-canonical-finding-model.md
006-contextual-risk-engine.md
007-kubernetes-scanner-jobs.md
```

Each ADR should explain:

- context
- decision
- alternatives
- rationale
- consequences

Claude Code should create an ADR before making major architectural changes where appropriate.

---

# 41. Important Anti-Patterns

Claude Code must avoid:

## Anti-pattern 1: One giant backend file

Do not put all orchestration, scanners, database operations, risk scoring, and API handlers into one package/file.

## Anti-pattern 2: Scanner-specific logic everywhere

Do not write:

```text
if scanner == trivy
if scanner == grype
if scanner == gitleaks
```

throughout the application.

Use adapters and interfaces.

## Anti-pattern 3: Synchronous scans

Do not block HTTP requests while long-running scanners execute.

## Anti-pattern 4: Scanner output directly in UI

The UI should consume SecureOps domain models/API responses.

## Anti-pattern 5: Fake AI

Do not label deterministic rules "AI."

## Anti-pattern 6: AI-generated remediation without validation

Never present hallucinated remediation as authoritative.

## Anti-pattern 7: Kubernetes-first development

Do not start by writing 40 Kubernetes YAML files before the application works.

## Anti-pattern 8: Overengineering

Do not introduce Kafka, Elasticsearch, microservices, service meshes, or other infrastructure unless a concrete requirement justifies them.

The project can be modular without becoming a distributed-systems hostage situation.

## Anti-pattern 9: Security through obscurity

Do not rely on hiding endpoints, obscure identifiers, or UI restrictions as the primary security mechanism.

## Anti-pattern 10: Ignoring the platform's own security

SecureOps is itself a security product.

Its API, workers, database, CI/CD, containers, dependencies, and deployment configuration must be assessed and hardened.

---

# 42. Practical Initial Architecture

The first production-capable development version should remain relatively simple:

```text
Next.js
   │
   ▼
Go API
   │
   ├─────────────── PostgreSQL
   │
   └─────────────── Redis
                       │
                       ▼
                 Scanner Worker
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
          Semgrep   Gitleaks   Trivy
             │         │         │
             └─────────┼─────────┘
                       ▼
                 Normalization
                       ▼
                  Correlation
                       ▼
                    Risk
                       ▼
                 Remediation
                       ▼
                   Policy
                       ▼
                  Dashboard
```

Then scale scanner execution and isolation through Kubernetes.

---

# 43. Long-Term Architecture

A mature version can evolve toward:

```text
                         ┌──────────────────┐
                         │    Next.js UI    │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │     Go API       │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
              PostgreSQL                    Redis
                    │                           │
                    │                     Job Queue
                    │                           │
                    │             ┌─────────────┼─────────────┐
                    │             ▼             ▼             ▼
                    │          Scanner        Scanner       Scanner
                    │           Jobs            Jobs          Jobs
                    │             │             │             │
                    │             └─────────────┼─────────────┘
                    │                           ▼
                    │                    Normalization
                    │                           │
                    │                           ▼
                    │                     Correlation
                    │                           │
                    │                           ▼
                    │                      Risk Engine
                    │                           │
                    │                           ▼
                    │                   Remediation Engine
                    │                           │
                    └───────────────────────────┤
                                                ▼
                                          Policy Engine
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                                  CI/CD                 Dashboard
```

Do not implement the mature architecture prematurely.

---

# 44. Suggested Dashboard

The dashboard should eventually resemble a security operations view rather than a generic CRUD application.

Main page:

```text
┌─────────────────────────────────────────────────────────┐
│ SecureOps                                      Project ▼ │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Security Score       Critical      High       Secrets   │
│     72/100              3           12           2      │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ Risk Trend                                               │
│                                                         │
│              ╭────╮                                     │
│         ╭────╯    ╰─────                                 │
│    ─────╯                                               │
│                                                         │
├───────────────────────┬─────────────────────────────────┤
│ Findings              │ Security Gate                   │
│                       │                                 │
│ Critical       3      │ FAILED                          │
│ High          12      │                                 │
│ Medium        27      │ 3 critical vulnerabilities      │
│ Low           41      │ 2 exposed secrets               │
│                       │                                 │
├───────────────────────┴─────────────────────────────────┤
│ Recent Scans                                             │
│                                                         │
│ Commit      Status       Score      Findings             │
│ abc123      Failed        41         17                  │
│ def456      Passed        91          2                  │
│ ghi789      Passed        88          5                  │
└─────────────────────────────────────────────────────────┘
```

The visual design should prioritize information hierarchy and actionability.

---

# 45. Project Narrative for Academic/Professional Use

SecureOps should be described as:

> A unified DevSecOps security assessment and policy platform that orchestrates heterogeneous security scanners, normalizes their outputs into a common vulnerability model, correlates related findings across security domains, calculates context-aware project risk, generates prioritized remediation guidance, and enforces configurable security gates through CI/CD.

The strongest differentiator is:

```text
Multiple scanners
        ↓
One security intelligence layer
```

Not:

```text
Multiple scanners
        ↓
One dashboard
```

---

# 46. What Must Be Added Compared With the Original Proposal

The original proposal is strong but incomplete.

The following additions are recommended:

```text
SAST
→ Semgrep

API Security
→ OWASP ZAP

Database
→ PostgreSQL

Asynchronous Processing
→ Redis + Workers

Canonical Finding Model
→ Required

Finding Fingerprinting
→ Required

Cross-Domain Correlation
→ Core innovation

Contextual Risk Scoring
→ Core innovation

Security Policy Engine
→ Required

CI/CD Security Gates
→ Required

Asset Inventory
→ Recommended

SBOM Management
→ Recommended

Vulnerability Lifecycle
→ Recommended

Authentication
→ Required

RBAC
→ Required

Audit Logging
→ Required

Threat Model
→ Required

Scanner Isolation
→ Critical

Resource Limits
→ Critical

Historical Analytics
→ Recommended

Observability
→ Recommended

Kubernetes
→ Later-stage deployment/scaling
```

---

# 47. Definition of Done

A feature is not complete merely because the code compiles.

For every feature, Claude Code should verify:

```text
[ ] Requirements understood
[ ] Existing architecture inspected
[ ] Implementation plan created
[ ] Code implemented
[ ] Unit tests added/updated
[ ] Integration tests added where appropriate
[ ] Formatting passes
[ ] Linting passes
[ ] Build passes
[ ] Security checks pass
[ ] Documentation updated where necessary
[ ] API contracts updated where necessary
[ ] Database migrations reviewed
[ ] Git diff inspected
[ ] No secrets introduced
[ ] No unrelated files changed
[ ] Known limitations documented
```

---

# 48. Final Instructions to Claude Code

When using this document to create `CLAUDE.md`:

1. Inspect the actual repository before generating the final file.
2. Do not assume that the repository already contains components described in this specification.
3. Clearly distinguish current repository state from intended architecture.
4. Generate a root-level `CLAUDE.md`.
5. Make `CLAUDE.md` practical for repeated Claude Code sessions.
6. Keep architectural rules explicit.
7. Include security constraints prominently.
8. Include scanner responsibilities.
9. Include the canonical finding model and normalization requirement.
10. Include correlation and risk-engine principles.
11. Include scanner isolation requirements.
12. Include testing and Definition of Done requirements.
13. Include Git safety rules.
14. Include instructions to inspect before modifying.
15. Include instructions to work phase-by-phase.
16. Include instructions not to make material architectural changes silently.
17. Do not implement the entire SecureOps platform during this task.
18. Do not delete existing project files.
19. Do not modify unrelated configuration.
20. Do not replace the MIT license.
21. Do not introduce unnecessary technologies.
22. Do not treat Claude Code or MCP as runtime dependencies of SecureOps.
23. After creating `CLAUDE.md`, review it for contradictions, duplication, and ambiguity.
24. Report exactly what was created or changed.
25. Do not commit unless explicitly instructed.

The immediate objective is:

```text
Repository
   ↓
Claude Code reconnaissance
   ↓
Generate robust CLAUDE.md
   ↓
Review CLAUDE.md
   ↓
Begin implementation phase-by-phase
```

---

# 49. Final Project Vision

SecureOps should ultimately behave like this:

```text
Developer pushes code
        │
        ▼
GitHub Actions
        │
        ▼
SecureOps
        │
        ├── SAST
        ├── Secrets
        ├── Dependencies
        ├── SBOM
        ├── Containers
        ├── IaC
        └── APIs
                │
                ▼
        Unified Findings
                │
                ▼
        Correlation Engine
                │
                ▼
        Contextual Risk
                │
                ▼
        Remediation
                │
                ▼
        Security Policy
                │
          ┌─────┴─────┐
          ▼           ▼
        PASS          FAIL
          │             │
          ▼             ▼
      Deployment     Block / Review
```

The core product principle is:

> **SecureOps should turn fragmented security scanner output into one contextual security decision.**

That is the architectural and product identity that should remain consistent across the codebase, documentation, UI, CI/CD integration, academic report, demonstration, and future extensions.

