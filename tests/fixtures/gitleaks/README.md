# Gitleaks fixtures

Captured and hand-edited gitleaks 8.30.1 JSON reports. Tests run against these
rather than executing gitleaks, so the deterministic parsing and the redaction
invariant are testable without the binary installed (CLAUDE.md §19).

| Fixture | What it covers |
|---|---|
| `redacted.json` | Normal output under `--redact`: the shape the adapter must accept. |
| `unredacted.json` | **The control case.** Secret and Match carry a value. The adapter must reject this and discard the output (ADR 007). |
| `redacted-with-context.json` | Match with surrounding context — `api_key = "REDACTED"`. This is correctly redacted output and must be accepted. An exact-match check rejected it, discarding every real `generic-api-key` finding. |
| `unredacted-match.json` | Secret is redacted but Match carries the value. The narrower case the split check exists to catch. |
| `empty.json` | A clean scan, `[]`. |
| `no-findings.json` | A zero-byte report — what gitleaks actually writes when it finds nothing. |
| `truncated.json` | Output cut mid-object, as a size cap or a killed process would leave it. |
| `malformed.json` | Not JSON at all, standing in for a crashed or wrapper-mangled run. |

**No fixture contains a real credential.** The value in `unredacted.json` is a
readable placeholder chosen so that a reader can see at a glance it is not a
live token, and so the repository's own gitleaks scan does not flag it.
