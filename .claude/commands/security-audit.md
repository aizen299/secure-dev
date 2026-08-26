---
description: Run the SecureOps self-scan and review the change against the security rules
---

SecureOps scans SecureOps. Run the self-scan, then review the current change
against the project's own security requirements.

**1. Run `make security`** — gitleaks (history and working tree), semgrep,
trivy, and syft/grype. Report each result. If a scanner binary is missing, say
so; never silently skip one.

**2. Review the change against CLAUDE.md §14 and §15.** Specifically:

- Does anything execute untrusted content on the API server? (§14.1)
- Is any subprocess built as a shell string rather than an argv? (§14.4, §25.11)
- Are paths canonicalised and contained? (§14.5)
- Are new outbound URLs SSRF-checked? (§14.6)
- Could any new log line or error message emit a secret, a DSN, or
  attacker-supplied input? (§15.3)
- Is every new SQL statement parameterised? (§15.9)
- Is every new external input size-bounded? (§15.8)
- Do new endpoints enforce authorization server-side? (§15.4)

**3. Check the threat model.** If the change moves a trust boundary, adds a
component, or changes a threat's status, `docs/security/threat-model.md` must be
updated in the same change (§15.14, §21).

If you find a finding, do not suppress it to get green. Fix it, or explain
precisely why it is not exploitable — with evidence, as ADR 005 does.
