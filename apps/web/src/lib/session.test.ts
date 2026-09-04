/**
 * @vitest-environment node
 */
import { describe, expect, it } from "vitest";
import { sessionLooksValid, SESSION_MAX_AGE_SECONDS } from "./session";

/**
 * The dashboard no longer decides whether a session is valid (ADR 033 §5a).
 *
 * ADR 029 had it mint and verify an HMAC cookie of its own, because there were
 * no users and the only question was "may this browser look at this?". Now the
 * API issues a session that carries who someone is, and a second signed value
 * would be a second answer to the same question — with the two able to disagree
 * about whether somebody is still signed in.
 *
 * So what is left here is a shape check, and these tests exist to pin that it
 * stays a shape check. If this file ever grows a signature verification again,
 * the dashboard has started asserting something only the API can know.
 */
describe("sessionLooksValid", () => {
  it("accepts something shaped like an API session", () => {
    expect(sessionLooksValid("usr_a-user-id.1788553637.deadbeefcafe")).toBe(true);
  });

  it("rejects absent, empty and malformed values", () => {
    for (const value of [undefined, "", "usr_", "usr_nodots", "a-user-id.123.abc", "hunter2"]) {
      expect(sessionLooksValid(value)).toBe(false);
    }
  });

  /**
   * It must NOT try to judge expiry or signature.
   *
   * A cookie whose token the API has revoked — a disabled account, a rotated
   * signing key — still looks fine here, and that is correct: the API re-reads
   * the user on every request and refuses it there. A dashboard that guessed
   * would be wrong in the dangerous direction, letting somebody through on a
   * shape.
   */
  it("does not claim a well-formed value is genuine", () => {
    // Signature is nonsense; the API would refuse it. This layer must not.
    expect(sessionLooksValid("usr_a-user-id.1.0000000000000000")).toBe(true);
  });
});

describe("SESSION_MAX_AGE_SECONDS", () => {
  // Must equal the API's own users.SessionTTL. A cookie expiring before or
  // after the token produces a session valid to one layer and not the other:
  // a sign-in that appears to work and then 401s on the first read, or a cookie
  // outliving a token nobody can use.
  it("matches the API's eight-hour session", () => {
    expect(SESSION_MAX_AGE_SECONDS).toBe(8 * 60 * 60);
  });
});
