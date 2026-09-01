# Semgrep fixtures

Captured from a real `semgrep scan` against a small Python project with two
deliberate flaws (an MD5 hash and `subprocess(shell=True)`), using the `p/python`
ruleset provisioned the way the adapter provisions it.

The deterministic engines are tested against these rather than against live
semgrep (§19): a test that shells out to a real scanner tests the scanner, and
cannot produce the hostile cases below at all.

| Fixture | What it is |
|---|---|
| `valid.json` | Two real findings. `extra.lines` reads `requires login` — unauthenticated semgrep withholds matched source. |
| `no-findings.json` | A clean project. Distinct from a failed scan, and the distinction is the point. |
| `source-leak.json` | `extra.lines` carries a credential. The case ADR 007 raised and ADR 014 answers: this must be refused, never stored. |
| `source-leak-benign.json` | `extra.lines` carries ordinary source, not a secret. Still refused — the control cannot tell the difference, and a control that tries to would eventually guess wrong. |
| `workspace-path-leak.json` | A finding path rooted in the worker's ephemeral workspace (T-30's shape, from syft). |
| `wrong-tool.json` | Valid JSON from something else (SARIF). Would otherwise be stored as if semgrep produced it. |
| `truncated.json` | Cut mid-object, as a size cap or killed process would leave it. |
| `malformed.json` | Structurally broken JSON. |
| `empty.json` | No output. Distinct from `no-findings.json`. |

`source-leak.json` carries a credential *assignment*, which is the shape that
matters, with a word-shaped placeholder value. A realistic key format would be
flagged by SecureOps' own gitleaks self-scan — the fixture is written to be
unambiguous rather than allowlisted, because allowlisting this directory would
mean a genuine secret committed here went unnoticed.
