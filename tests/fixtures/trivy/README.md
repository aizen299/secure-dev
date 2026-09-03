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
| `redacted.json` | What the adapter actually persists: the same report with `Content`, `Highlighted`, and `Annotation` replaced. This is the input normalization consumes. |
| `unredacted-after-rewrite.json` | Source planted back into a line, standing in for a trivy schema change the rewrite walks past. Proves the assertion catches what the rewrite misses. |
| `no-findings.json` | A clean project. Distinct from a failed scan, and the distinction is the point. |
| `wrong-tool.json` | Valid JSON from something else (SARIF). Would otherwise be stored as if trivy produced it. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Structurally broken JSON. |
| `empty.json` | No output. Distinct from `no-findings.json`. |
| `image-vulnerable.json` | **Real** `trivy image` output for `alpine:3.9`, 14 vulnerabilities. The `ArtifactType: container_image` report the image mapper reads. |
| `image-clean.json` | Real output for `alpine:3.14`, no vulnerabilities. A clean image is not a failed scan. |
| `image-express.json` | Real output for an image with `express@4.17.1` installed. Pairs with `grype/image-correlation-repository.json` to demonstrate §9's worked example. |
| `image-hostile.json` | Written, not captured: an impossible CVSS, a PURL carrying the fingerprint field separator, a `fixed` state naming no version, a version attached to `wont-fix`, and an entry identifying nothing. |

The password in `unredacted.json` is a word-shaped placeholder. A realistic
value would be flagged by SecureOps' own gitleaks self-scan — the fixture is
written to be unambiguous rather than allowlisted, because allowlisting this
directory would mean a genuine secret committed here went unnoticed.

`ArtifactName` is rewritten to `.` in every fixture: trivy records the absolute
scan path there, and committing a developer's home directory layout is the
T-30 problem in a different costume.

The image fixtures keep their real `ArtifactName`, unlike the filesystem ones.
For an image report that field is the reference trivy was pointed at — it is the
input identity is derived from, not a leaked scan path, so the T-30 rewrite does
not apply to it.
