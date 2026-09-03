# Grype fixtures

Captured from a real `grype dir:` run against a Go module pinned to
`golang.org/x/crypto v0.31.0`, then trimmed to three matches. The host's
database cache path was replaced with the container path — a fixture must not
carry the machine that produced it.

The deterministic engines are tested against these rather than against live
grype (§19): a test that shells out to a real scanner tests the scanner, not the
code under test, and cannot exercise the cases below at all.

| Fixture | What it is |
|---|---|
| `valid.json` | A normal report: three matches, fresh database. |
| `no-matches.json` | A clean project. Distinct from a failed scan, and the distinction is the point. |
| `stale-db.json` | Database built 2024-01-05. Must degrade, not fail — the matches it did find are real. |
| `invalid-db.json` | `status.valid: false`. Grype declaring its own data unusable, which is refused rather than degraded. |
| `no-db-provenance.json` | No `descriptor.db` at all. Freshness unprovable; silence is not evidence of freshness. |
| `no-built-timestamp.json` | `db.status` present, `built` absent. Same verdict, different shape. |
| `unparseable-built.json` | `built` is not RFC3339. A timestamp that cannot be read proves nothing. |
| `wrong-tool.json` | `descriptor.name: trivy`. Valid JSON from the wrong tool, which would otherwise be stored as if grype produced it. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Structurally broken JSON. |
| `empty.json` | No output. Distinct from `no-matches.json`. |
| `image-correlation-repository.json` | **Real** grype output for a repository declaring `express@4.17.1`. Pairs with `trivy/image-express.json` to demonstrate §9's worked example: both scanners emit `pkg:npm/express@4.17.1` byte for byte, which is what the correlation joins on. The grype DB cache path is rewritten to `/var/cache/grype`, per T-30. |

Nothing here contains a real credential. The advisories referenced are public.
