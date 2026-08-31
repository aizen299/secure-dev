# ADR 011: The API contract is enforced by tests, not by a spec linter

- **Status:** Accepted
- **Date:** 2026-09-01

## Context

§18 requires `docs/api/openapi.yaml` to stay in sync with the handlers — "an API
change with no spec change is incomplete" — and §25.17 forbids changing a public
API contract silently.

Neither was enforced by anything. A handler could gain, lose, or rename a field
and all five CI jobs would pass. The rule existed; the mechanism did not. This
was noticed while making exactly that kind of change (ADR 010 replaced
`truncated: bool` with `degradations: string[]`), where nothing but discipline
connected the two edits.

The obvious fix is a spec linter. The obvious fix is insufficient: **a spec can
be perfectly valid and describe an API the handlers no longer serve.** Linting
the YAML checks the document against the OpenAPI meta-schema, not against the
system. It would have caught none of the drift §18 is about.

## Decision

Enforce the contract in Go, as ordinary tests, using `pb33f/libopenapi` and
`pb33f/libopenapi-validator` (both MIT). Three checks, in
`internal/httpapi/openapi_contract_test.go`:

1. **`TestOpenAPISpecIsValid`** — the document parses as OpenAPI 3.1 and
   validates. The weak check, and explicitly labelled as such in the code.
2. **`TestEveryRouteIsDocumented`** — walks the real chi router and compares it
   against the spec's paths **in both directions**: a route with no
   documentation, and documentation for a route nothing serves.
3. **`TestOpenAPIMatchesHandlers`** — drives the real handlers and validates
   every response against the schema the spec publishes for that route and
   status. This is the one that enforces §18.

`make lint-api` runs them; CI runs `make lint-api` as its own step so a contract
break reads as a contract break rather than as "some test failed".

## Alternatives considered

**Redocly CLI.** MIT, full 3.1 support, and a real candidate. Rejected on two
counts: it has runtime telemetry (opt-out via `REDOCLY_TELEMETRY`), which sits
badly beside the deliberate refusal of `semgrep --config auto` for the same
reason; and it validates the spec only, so it cannot detect drift. Adopting it
would have satisfied the letter of "CI validates the spec" while leaving the
actual §18 requirement unenforced.

**Spectral.** Apache-2.0, and the more capable linter of the two. Rejected: it
pulls `@scarf/scarf` transitively through four of its own packages, which runs
an analytics reporter as a `postinstall` script — telemetry at install time,
in CI, on every run. Same drift blindness as Redocly.

Both would also have put Node in the `go` job, or added a job to carry it.

**Generate the spec from Go annotations.** Rejected: it inverts the
relationship. The spec would become a derivative of the handlers, so the two
could never disagree — and could never disagree is not the same as agree. A
contract that is generated from the implementation cannot constrain it. It is
also invasive, requiring annotations throughout the handlers.

**Leave it to review.** The status quo, and the reason this ADR exists.

## Consequences

- **No new toolchain in CI.** It is `go test`, with dependencies pinned through
  `go.mod` like everything else. No Node, no separately-installed linter, no
  pinned action.
- Two new dependencies, test-only in practice but ordinary `require` entries.
  They pulled `golang.org/x/net` forward to a version carrying five HIGH
  advisories; bumped to v0.56.0, which the self-scan confirmed clean. Adding any
  dependency drags its transitive set with it, and `make security` is what
  catches that.
- **The weak check is weaker than a real linter.** `ValidateDocument` caught
  malformed YAML and a dangling `$ref` when tested, but did **not** reject a
  schema with an invalid `type` keyword that no path referenced. Whether it
  rejects one on a referenced schema was not established. If exhaustive spec
  linting is wanted later, Redocly can be added *alongside* this — the two solve
  different problems, and this ADR rejects Redocly as a *substitute*, not as a
  supplement.
- Only responses are validated. Request validation would re-test the handlers'
  own input validation, which is covered directly elsewhere; what had no
  coverage is whether what we send matches what we published.
- `TestOpenAPIMatchesHandlers` walks a hand-written list of routes, so it can
  only check what it is told to exercise. That hole is why
  `TestEveryRouteIsDocumented` exists: a new endpoint cannot be silently
  omitted from the contract, even if nobody adds it to the case list.
- Each check was verified by breaking it: a dangling `$ref`, malformed YAML, a
  renamed handler field, a dropped required field, an undocumented route, and a
  documented route with no handler each make the corresponding test fail.
