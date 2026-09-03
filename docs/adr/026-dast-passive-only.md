# ADR 026: DAST with ZAP — passive only, and what a DAST finding is

- **Status:** Proposed
- **Date:** 2026-09-03

## Context

ZAP is the last adapter in Phase 3b and the only one that scans a **running
application** rather than a checkout or an artifact. That difference is not
incidental; it is the whole decision. Every other adapter reads bytes at rest.
This one sends HTTP requests to a live host, and what it is permitted to send is
a question no previous adapter has had to answer.

`KindEndpoint` has been modelled and validated since Phase 2, and `POST /scans`
accepts it. Unlike `KindImage` before ADR 025, `validateEndpoint` **does**
already apply the SSRF address policy, so there is no latent hole here — the
gap that image targets exposed was checked for and is genuinely absent.

### What was measured first

ZAP 2.17.0, run headless against a local target under the Automation Framework
(`spider` → `passiveScan-wait` → `report`, `traditional-json`):

- **It runs headless and reproducibly.** `zap.sh -cmd -autorun plan.yaml`
  produces a JSON report with no GUI and no daemon left running. The plan is
  data, which matters for the same reason semgrep's pinned rulesets do
  (ADR 014): the scan must be reproducible, not dependent on ambient state.
- **`riskcode` tops out at 3 (High).** ZAP has no "critical".
- **The report embeds credentials.** This is the finding that shaped the design.
  Against a target serving a link to `/search?api_key=…`, a hidden form token,
  and a session cookie:

  | Planted value | Where it lives | Occurrences |
  |---|---|---|
  | Query-string API key | `instances[].uri` | **7** |
  | Hidden form field value | `alerts[].otherinfo`, `instances[].otherinfo` | **2** |
  | Value inside a `<script>` | — | 0 |
  | Session cookie value | — | 0 (ZAP reports the cookie *name* only) |

  So ZAP is careful about cookies and careless about URLs. A single request to
  an endpoint whose query string carries a token puts that token in the report
  once per alert that touched the URL.

## Decision

### 1. Passive scanning only. No active scan, ever, without a separate decision

The adapter runs `spider` and `passiveScan-wait`. It does **not** run
`activeScan`, and the job is absent from the plan rather than disabled in it.

Active scanning is not "more thorough passive scanning". It sends crafted
attack payloads — SQL injection, XSS, command injection, path traversal — at a
live application. Three consequences, none of which SecureOps can currently
manage:

- **It changes state.** A payload delivered to a real form submits that form.
  Active scanning against anything with a database writes to that database.
- **It is attack traffic.** Whether it is authorized depends on who owns the
  target, and SecureOps has no per-target authorization model — a project can
  name any endpoint the address policy permits. A tool that sends attack traffic
  on the strength of a URL somebody typed is a tool that will eventually be
  pointed at a host its operator does not own.
- **It needs a scope nobody has declared.** ZAP's own guidance is that active
  scanning is for systems you have permission to test. That permission is a
  fact about a deployment, not a flag on a scan.

Passive scanning observes the traffic the spider already generated and reports
on what it sees: missing headers, cookie flags, information disclosure,
absent CSRF tokens. It sends no payloads. Every request it causes is a request a
browser would have made.

This is a real reduction in what DAST finds, and it is stated rather than hidden:
**SecureOps does not test for injection.** Active scanning is a future decision
requiring a per-project authorization model, and it belongs to the project owner
(§24), not to this ADR.

### 2. Identity: the URL path, not the origin

A DAST finding's fingerprint uses the existing five-field `FingerprintInput`:

| Field | Value |
|---|---|
| `Category` | `dast` |
| `RuleID` | ZAP's `alertRef` (e.g. `10038-1`), which is more specific than `pluginid` |
| `Location` | the URL **path**, with the origin and the query string removed |
| `Package` | empty |
| `VulnerabilityID` | empty |

So `https://pr-4821.preview.example.com/login?next=/home` contributes `login`.

**The origin is excluded** for the reason ADR 025 excluded the image tag: it
churns. CI preview environments mint a new hostname per pull request, so an
origin in the identity would resolve every finding and open an identical set on
every PR. Excluding it is safe because findings are unique per
`(project_id, fingerprint)` — two projects scanning two deployments never
collide. Two *hosts of one project* do merge, which is the deliberate trade: the
same missing header on staging and production is one problem, fixed once.

**The query string is excluded** because it is where the credentials are, and
because it is per-request noise. `?next=/home` and `?next=/settings` are not two
findings.

**No new fingerprint field**, for the arithmetic reason ADR 025 records: the
fields are joined with a separator, so a sixth changes the bytes for every
finding already stored, image and repository findings included.

**What this costs, stated plainly.** Method and parameter are *not* in the
identity. `GET /items` and `POST /items` produce one finding per rule, and a
rule firing on two parameters of one path is one finding with two occurrences.
For ZAP's passive rules this is almost always right — they are page-level
(headers, cookies, forms) and the fix is one change to one endpoint. For a
future active scan it would be wrong, and that is one more thing active scanning
would have to settle before it lands.

### 3. Redaction, and this time a hash rather than only a marker

ZAP output is rewritten before it is persisted. This is the second adapter to do
so, after trivy (ADR 015), and for the same reason: §15.3 forbids storing a
detected secret, and the measurement above shows the report carries them.

Four fields are treated:

- **`instances[].uri`** — the query string is stripped, the path kept. This one
  rewrite serves redaction *and* identity, because the query is exactly what
  makes a URL both secret-bearing and unstable.
- **`instances[].evidence`** — replaced.
- **`alerts[].otherinfo` and `instances[].otherinfo`** — replaced.
- **`instances[].attack`** — replaced. Always empty without active scanning, and
  treated anyway, so the control does not depend on the scan mode staying as it
  is today.

Where trivy replaces source lines with a bare `[redacted]`, this adapter stores
`[redacted:<sha256-prefix>]`. §15.3 asks for "a location and a hash, not the
secret", and a hash buys something a marker does not: two scans can be compared,
and a person can confirm whether the evidence changed, without the value ever
being stored. The hash is of the original field content and is truncated to 16
hex characters, which is far too short to attack a high-entropy secret by
brute force and long enough to be stable.

Redaction is verified after it runs and the report is discarded if anything
survived — the same fail-closed check trivy uses, for the same reason: a walk
that misses a renamed field must not silently persist credentials.

### 4. Egress, credentials, and telemetry

- `NetworkKinds: []Kind{KindEndpoint}`. The per-kind egress declaration added by
  ADR 025 pays for itself here: this adapter needs the network for the only
  kind it serves, and the declaration says exactly that.
- **No authentication.** ZAP can log in to an application; workers hold no
  credentials (§14.7), so scans are unauthenticated and reach only what an
  anonymous visitor reaches. Authenticated DAST needs a credential-handling
  decision, and is out of scope with active scanning.
- **Telemetry off, explicitly.** ZAP's `callhome` add-on reports version and
  usage. It is disabled by `-silent` and again by explicit configuration, the
  same posture ADR 014 takes toward semgrep's `--config auto`: a scan must not
  be conditional on a vendor endpoint being reachable, and must not report our
  usage to one.

### 5. No `endpoint:` correlation key yet

`internal/correlation/key.go` names `endpoint:<method> <path>` as the one
remaining future key. It is still not added, and the test is the one ADR 025
applied to `image:`: *does this key let the engine assert something true it
could not otherwise assert?*

Today, no. Only ZAP produces endpoint locations, so every member of an
`endpoint:` bucket has category `dast` — and `formIssue` requires two distinct
categories, while `linkFor`'s co-location rule explicitly returns nothing when
categories match. The key would be inert: no issues, no links, one more constant.

It becomes justified the moment a second source of endpoint data exists — an
OpenAPI import, or a SAST rule that knows which handler serves a route — because
then the bucket is genuinely cross-domain. That is when to add it, and the note
in `key.go` is updated to say so rather than to promise it.

## Alternatives considered

**Active scanning, gated behind a per-project flag.** The obvious answer, and it
fails on where the flag lives. A boolean on a project record is not authorization
to attack a host; it is a checkbox somebody ticked. Real authorization is a
statement about ownership of the target, and modelling it is a larger piece of
work than this adapter.

**A `zap-baseline.py` wrapper instead of the Automation Framework.** The baseline
script is the well-known entry point and it hides its configuration in flags and
exit codes. The Automation Framework takes a declarative plan, which is data the
adapter writes and a test can assert — the same reason semgrep's rulesets are
pinned in the argument vector where a test can see them.

**Include the origin in identity.** Correct for a fixed-host deployment, wrong
for the CI preview environments that DAST is most useful in, and wrong in the
direction that destroys lifecycle continuity rather than the direction that
merges two records.

**Redact evidence wholesale, as trivy does.** Consistent, and it throws away the
one thing that makes a DAST finding actionable at a glance. The hash keeps the
control and returns comparability.

**Keep the query string and redact only values that look like secrets.** That is
pattern-matching against an unbounded space, and being wrong means storing a
credential. Stripping the whole query is the version that cannot be wrong.

## Consequences

**What becomes possible.** `KindEndpoint` stops being a modelled kind that always
fails, and Phase 3b's adapter list is complete. A project can scan a deployed
application and get findings in the same model as everything else.

**What becomes harder.** The worker needs egress to the target — declared, and
still unenforced until Phase 12 (T-51 covers the same gap for registries). And
ZAP is a Java application: shipping it means a JRE in the worker image, which is
a substantial infrastructure change and is deliberately **not** part of this one.
Until it lands, an endpoint scan in a deployed worker degrades through the
existing "scanner binary missing" path, which is tested. The adapter is developed
and verified against a local ZAP and captured fixtures, which is what §6 asks
for.

**What we are committed to.** A DAST finding's identity is its rule and its path.
Adding method or parameter later is a re-fingerprinting migration.

**What is explicitly not solved.** No injection testing, no authenticated
scanning, no API-schema-driven crawling (ZAP's OpenAPI add-on is present and
unused), and no scan-scope model beyond the address policy. Each is a real
limitation of the DAST coverage, and each is named here rather than discovered
later.
