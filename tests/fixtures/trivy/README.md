# Trivy fixtures

Captured from a real `trivy fs --scanners misconfig` against a small project
containing a Dockerfile that runs as root and a Terraform resource with a
hardcoded password.

The deterministic engines are tested against these rather than against live
trivy (§19): a test that shells out to a real scanner tests the scanner, and
cannot produce the hostile cases below at all.

| Fixture | What it is |
|---|---|
| `unredacted.json` | **As trivy actually emits it** — `CauseMetadata.Code.Lines[]` carries `Content` and `Highlighted`, both holding source. This is the input redaction must clean, and the reason ADR 015 exists. |
| `unredacted-after-rewrite.json` | Source planted back into a line, standing in for a trivy schema change the rewrite walks past. Proves the assertion catches what the rewrite misses. |
| `no-findings.json` | A clean project. Distinct from a failed scan, and the distinction is the point. |
| `wrong-tool.json` | Valid JSON from something else (SARIF). Would otherwise be stored as if trivy produced it. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Structurally broken JSON. |
| `empty.json` | No output. Distinct from `no-findings.json`. |

The password in `unredacted.json` is a word-shaped placeholder. A realistic
value would be flagged by SecureOps' own gitleaks self-scan — the fixture is
written to be unambiguous rather than allowlisted, because allowlisting this
directory would mean a genuine secret committed here went unnoticed.

`ArtifactName` is rewritten to `.` in every fixture: trivy records the absolute
scan path there, and committing a developer's home directory layout is the
T-30 problem in a different costume.
