/**
 * @vitest-environment node
 */
import { describe, expect, it, vi } from "vitest";

/**
 * How the dashboard reads an API refusal (ADR 033).
 *
 * 401 and 403 used to be one predicate, `isUnauthorized`, back when every read
 * travelled on the dashboard's own service token and either could only mean the
 * deployment was misconfigured. Since reads travel on the signed-in person's
 * session they are different facts with different remedies, and conflating them
 * sends people to the wrong place: to the login form when their account merely
 * lacks a role, or to the infrastructure when they only needed to sign in.
 */

const redirect = vi.fn((path: string) => {
  // Next's own redirect throws to unwind the render. Mirrored here so a caller
  // that forgets it does not fall through -- which is the mistake this helper
  // exists to make impossible.
  throw new Error(`NEXT_REDIRECT:${path}`);
});

vi.mock("next/navigation", () => ({
  redirect: (path: string) => redirect(path),
}));
vi.mock("server-only", () => ({}));
vi.mock("./guard", () => ({ sessionToken: async () => "usr_test" }));

const { ApiError, redirectIfSessionExpired } = await import("./api");

describe("ApiError", () => {
  it("separates a dead session from a refusal", () => {
    expect(
      new ApiError(401, "unauthenticated", "valid credentials are required")
        .isSessionExpired,
    ).toBe(true);
    expect(
      new ApiError(401, "unauthenticated", "valid credentials are required")
        .isForbidden,
    ).toBe(false);

    expect(
      new ApiError(403, "forbidden", "this credential is not permitted")
        .isForbidden,
    ).toBe(true);
    // The one that matters: a 403 must NOT send somebody to the login form.
    // They are already signed in, and signing in again changes nothing.
    expect(
      new ApiError(403, "forbidden", "this credential is not permitted")
        .isSessionExpired,
    ).toBe(false);
  });
});

describe("redirectIfSessionExpired", () => {
  it("sends an expired session to the login form", () => {
    expect(() =>
      redirectIfSessionExpired(
        new ApiError(401, "unauthenticated", "valid credentials are required"),
      ),
    ).toThrow("NEXT_REDIRECT:/login?error=expired");
  });

  it("leaves a 403 alone", () => {
    expect(() =>
      redirectIfSessionExpired(
        new ApiError(403, "forbidden", "this credential is not permitted"),
      ),
    ).not.toThrow();
  });

  it("leaves an outage alone", () => {
    // "The API did not answer" is a real state with its own page. Redirecting
    // to the login form would tell somebody their session ended when it did
    // not, and signing in would fail for the same underlying reason.
    expect(() =>
      redirectIfSessionExpired(
        new ApiError(502, "bad_gateway", "upstream failed"),
      ),
    ).not.toThrow();
    expect(() =>
      redirectIfSessionExpired(new TypeError("fetch failed")),
    ).not.toThrow();
  });
});
