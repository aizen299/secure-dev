---
description: Check the current change for architectural drift against CLAUDE.md
---

Review the working tree against the architecture rules. Report violations with
file and line; report "no drift" only after actually checking.

**Scanner abstraction (§7)**
- Any `if scanner == "..."` or `switch scanner` outside `internal/scanners/**`?
- Does anything outside an adapter import a scanner-specific parsing type?
- Would adding a new scanner require changes beyond its own package plus one
  registration line? If yes, the abstraction has leaked — stop and fix it.

**Boundaries**
- Does the API execute scanners, builds, or package managers? (§14.1, §25.1)
- Does any HTTP handler block on scanner execution? (§13, §25.2)
- Does raw scanner output reach the UI or a core engine unnormalized? (§25.4)

**Determinism**
- Is normalization pure — raw bytes to findings, no I/O? (§8)
- Is the risk engine free of I/O and of any AI influence? (§10)
- Is dedup by fingerprint rather than title or fuzzy similarity? (§8, §25.5)

**Contracts and docs**
- Does an API change have a matching `docs/api/openapi.yaml` change? (§18)
- Does a material architectural decision have an ADR *written first*? (§24)
- Are the fingerprint strategy and risk formula documented before their
  implementation? (§21)

**Structure**
- Are orchestration, persistence, scoring, and handlers in separate packages?
  (§25.12)
- Any new dependency without a stated reason? (§22)

For anything material (§24), stop and require an ADR plus owner approval rather
than proceeding.
