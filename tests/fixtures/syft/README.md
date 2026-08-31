# Syft fixtures

Captured and hand-trimmed syft 1.51.0 CycloneDX output. Tests run against these
rather than executing syft, so parsing and the SBOM invariants are testable
without the binary installed (CLAUDE.md §19).

| Fixture | What it covers |
|---|---|
| `valid.json` | Normal output: the shape the adapter must accept. |
| `no-components.json` | A repository with no recognised manifests. A legitimate result, **not** an error — treating it as one would fail every scan of a repository with no dependencies. |
| `workspace-path-leak.json` | **The control case.** A file component named by absolute workspace path. The adapter must reject this: it would make the SBOM differ between two scans of the identical commit. |
| `spdx.json` | A realistic SPDX document. Rejected for its missing `specVersion` — correct, but it does **not** exercise the format check. |
| `wrong-format.json` | Has a `specVersion`, so the `bomFormat` check is the only thing that can reject it. Without this, disabling that check leaves every test green. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Not JSON at all. |
| `empty.json` | Zero bytes — distinct from an empty component list. |

No fixture contains a credential; SBOMs describe packages, not secrets.
