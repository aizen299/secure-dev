# Fingerprinting

A fingerprint is a finding's **identity**: the thing that stays the same when the
same problem is seen again in a later scan. It is what makes a finding's
lifecycle — open, acknowledged, resolved, reopened — survive re-scanning, and
CLAUDE.md §8 requires it to be documented here before it is implemented.

Everything else about a finding can change between scans. The line it sits on
moves when code above it is edited. Its title changes when the scanner is
upgraded. Its severity changes when a vendor rescores a CVE. None of those may
be part of its identity.

## Why not the scanner's own fingerprint

Three of the five scanners were checked. None is usable:

| Scanner | What it provides | Why it cannot be used |
|---|---|---|
| Gitleaks | `config/settings.py:github-pat:2` | `file:rule:**line**`. Insert a line above the secret and the identity changes. |
| Semgrep | `extra.fingerprint` | Withheld as `requires login` in the unauthenticated configuration SecureOps runs (ADR 014). |
| Trivy | nothing | No per-finding identifier beyond the rule ID. |
| Grype | nothing | Identity is implicit in CVE + package. |
| Syft | n/a | Produces components, not findings. |

Gitleaks' is the instructive one: it is a real fingerprint, and it is unstable in
exactly the way §8 forbids. Adopting it would mean every finding below an edit
appearing as newly discovered, and every one above it as resolved.

## The fingerprint

```text
fingerprint = SHA256(
    category      ␟ rule_id      ␟ location
                  ␟ package      ␟ vulnerability_id
)
```

Fields are joined with `␟` (US, `0x1f`) rather than concatenated. A naive
concatenation is ambiguous: `"ab" + "c"` and `"a" + "bc"` produce the same
string, so two different findings could collide. `0x1f` cannot appear in any
normalized field, and normalization rejects it if it does.

### The inputs

| Input | Normalization | Empty when |
|---|---|---|
| `category` | lowercase enum: `secret`, `sast`, `dependency`, `iac`, `container`, `dast` | never |
| `rule_id` | trimmed, lowercased — the scanner's stable rule identifier (`github-pat`, `DS-0002`, a semgrep `check_id`) | the finding is identified by CVE rather than by rule |
| `location` | repository-relative, forward slashes, `path.Clean`, no leading `./` or `/`. For a container finding the **image repository**, for a DAST finding the **URL path** — see below | the finding has no file, image, or path (a dependency) |
| `package` | the purl when the scanner gives one, else `name@version` lowercased | the finding is not about a package |
| `vulnerability_id` | trimmed, uppercased (`CVE-2026-1234`, `GHSA-xxxx-…`) | the finding is not a known vulnerability |

### Container findings: what `location` holds

A container finding has no file. What it has instead is an image, and that is
what `location` carries — with the tag and the digest stripped:

```text
ghcr.io/org/myapp:1.2.3@sha256:abc…   →   ghcr.io/org/myapp
```

Both halves of that are load-bearing.

**The repository must be in the identity.** Without it, two different images
that happen to ship the same vulnerable package collapse into one finding. They
are different assets, deployed separately and fixed separately, and merging them
would report one problem where there are two.

**The tag and digest must not be.** They change on every build. Including them
would resolve every finding and open an identical set of new ones each time the
image was rebuilt, which is not an identity — it is a timestamp.

Nothing is added to the field list for this. A sixth input would change the
joined bytes for *every* finding, including the ones already stored, because the
fields are joined with a separator and an empty sixth field still adds one. That
would re-identify the entire database to describe images. Reusing `location`
leaves every existing fingerprint untouched, and `category` keeps a container
finding from colliding with a file of the same name — it is in the fingerprint,
and only image targets produce `container`. See ADR 025.

Two further normalizations happen in the trivy adapter rather than here, because
both are facts about that scanner rather than about identity:

- **PURL qualifiers are stripped.** Trivy appends `?arch=x86_64&distro=3.9.6` to
  OS-package PURLs. `distro` tracks the base image's patch level, so leaving it
  in would change a finding's identity when the base image was patched and the
  vulnerability was not.
- **The repository is lowercased.** Registry hosts are case-insensitive and
  repository paths are required to be lowercase, so two spellings must not
  become two findings.

A vulnerability naming neither a component nor an identifier is **refused**. The
repository alone is distinguishing input, so `Fingerprint` would accept it — and
every such entry in one image would then collapse onto that one identity,
merging unrelated defects. The adapter rejects it before fingerprinting.

### DAST findings: what `location` holds

A DAST finding has no file either. What it has is a URL, and `location` carries
its **path** — origin and query string removed:

```text
https://pr-4821.preview.example.com/login?next=/home   →   login
```

The reasoning mirrors the container case, inverted. For an image the repository
is the stable part and the tag is not; for a URL the path is the stable part and
the origin is not. A CI preview environment mints a new hostname per pull
request, so an origin in the identity would resolve every finding and open an
identical set on the next PR.

Excluding the origin is safe because findings are unique per
`(project_id, fingerprint)`: two projects scanning two deployments never
collide. Two hosts *within one project* do merge, which is the deliberate trade
— the same missing header on staging and production is one problem, fixed once.

The query string is excluded twice over: it is per-request noise, and it is
where an application carries credentials. Removing it serves identity and
§15.3 with one rewrite. Measured, not assumed — a target serving one link to
`/search?api_key=…` put that key in seven places in a single ZAP report.

**Method and parameter are not in the identity.** `GET /items` and `POST /items`
produce one finding per rule, and a rule firing on two parameters of one path is
one finding with two occurrences. For ZAP's passive rules this is almost always
right: they are page-level — headers, cookies, forms — and the fix is one change
to one endpoint. It would be wrong for an active scan, which is one more thing
active scanning would have to settle before it lands. The method is recorded on
the finding for a reader; it is not fingerprinted. See ADR 026.

### What is deliberately excluded

**Line and column.** The single most important exclusion. A finding that moves
when unrelated code is inserted above it is a finding whose history restarts on
every commit. Lines are recorded on the *occurrence*, not the identity.

**Title, description, message.** They change with scanner upgrades, and §25.5
forbids deduplicating on title or fuzzy similarity in any case.

**Severity.** A vendor rescoring a CVE would fork one finding into two.

**Scanner name and version.** Two scanners reporting the same CVE on the same
package are reporting *the same problem*, and §9's correlation depends on being
able to see that. The scanner is recorded as a field on the finding, and is
queryable; it is simply not part of identity.

**The secret value.** Not stored at all (§15.3), so not available to fingerprint
even if it were desirable.

### How the exclusions interact

Because `scanner` is excluded but `rule_id` is included, the formula behaves
differently — and correctly — for the two kinds of finding:

- **Rule-based** findings (secrets, SAST, IaC) carry a scanner-specific
  `rule_id`, so they are naturally scoped to the scanner that has that rule.
  Gitleaks' `github-pat` and a semgrep rule for the same thing stay distinct
  findings, and are linked by correlation rather than merged.
- **Vulnerability-based** findings carry an empty `rule_id` and a CVE plus a
  package, so grype and a future scanner reporting `CVE-2026-1234` on
  `pkg:golang/x/crypto@v0.31.0` produce **the same fingerprint** and deduplicate
  into one finding with two sources. That is the desired behaviour, and it falls
  out of the formula rather than needing a special case.

## Deduplication semantics

§8 requires four relationships, and forbids merging things because they look
similar. Only the first merges:

| Relationship | Test | Effect |
|---|---|---|
| **exact duplicate** | identical fingerprint | one finding, multiple occurrences and sources |
| **likely duplicate** | same `category` + `location` + `package`, different `rule_id` | **linked**, with a confidence value; never merged |
| **related** | shares a package, CVE, or file but not the above | linked as evidence for correlation (§9) |
| **independent** | none of the above | untouched |

A likely duplicate is a *claim*, not a merge. Two rules firing on one line are
often two genuine findings, and collapsing them loses one.

## Lifecycle: what a scan is entitled to resolve

A stable fingerprint is what makes `resolved` possible, but it does not by
itself say *when* a finding is allowed to become resolved. That question is a
security question, not a bookkeeping one: a finding wrongly marked resolved is
SecureOps telling someone a vulnerability was fixed when nobody checked.

The rule is narrow on purpose:

> A finding resolves only when **every scanner that has ever reported it**
> completed successfully in the scan, and none of them reported it.

Two failure modes this rules out:

- **A scanner that did not run.** A scan of only Gitleaks says nothing about
  Semgrep's findings. Resolving them would be the same error as reporting a
  `PARTIAL` scan as clean (§13, [ADR 010](../adr/010-scanner-degradation-reasons.md)).
- **A scanner that ran while its co-reporter failed.** `findings.scanner`
  records who reported a finding *first*, and a check written against that
  column alone resolves a Grype+Trivy finding the moment Grype comes back
  clean — even though Trivy failed and was never asked. The full set of
  reporters lives in `finding_occurrences`, and every one of them has to have
  had its say.

The cost is that dropping a scanner from a project's selection leaves that
scanner's old findings open indefinitely, because no scan will ever complete
with it again. That is the direction to be wrong in: stale-but-open is a state
someone can see and act on, and a false `resolved` is not.

## The known cost

Excluding the line number means **two instances of the same rule in the same
file share one fingerprint**. Two different hardcoded credentials in
`config/settings.py`, both matching `github-pat`, are one finding with two
occurrences rather than two findings.

This is a deliberate trade and it is the right one:

- The remediation is the same either way — remove the credentials from the file.
- The occurrences carry the individual line numbers, so nothing is hidden.
- The alternative loses lifecycle continuity for *every* finding in order to
  distinguish a minority of them.

It cannot be improved by hashing the secret, because SecureOps does not store
secret values (§15.3) and so has nothing to hash.

## Stability requirements

These are the properties the unit tests assert, including near-miss cases as
§8 requires:

1. **Deterministic** — the same finding fingerprints identically, always.
2. **Stable across line movement** — inserting or deleting lines elsewhere in a
   file does not change any fingerprint in it.
3. **Stable across scanner upgrades** — a changed title, message, or severity
   does not change the fingerprint.
4. **Distinct across near misses** — a different rule, a different file, a
   different package version, or a different CVE each produce a different
   fingerprint.
5. **Not collidable by construction** — no combination of field values can make
   two different findings produce one fingerprint, which is what the `0x1f`
   separator and the rejection of `0x1f` inside fields guarantee.
