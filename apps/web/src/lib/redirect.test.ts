/**
 * @vitest-environment node
 */
import { describe, expect, it } from "vitest";
import { redirectTo } from "./redirect";

/**
 * The `Location` header must stay relative (ADR 031's third category: a
 * refusal, in this case a refusal to decide what the host is).
 *
 * `NextResponse.redirect(new URL(path, request.url))` resolves against the
 * request as the *server* saw it -- inside Docker, the container's own
 * hostname. Signing in sent the browser to a host it could not resolve, and the
 * symptom was a login form that appeared to do nothing.
 *
 * The obvious repair, rebuilding the URL from `Host` or `X-Forwarded-Host`,
 * means trusting a client-supplied header to decide where to send a browser
 * that is carrying a freshly minted session cookie. A relative Location has no
 * host to trust, so this test guards a security property and not only a bug.
 */
describe("redirectTo", () => {
  it("emits a relative Location, never an absolute URL", () => {
    const location = redirectTo("/").headers.get("location");

    expect(location).toBe("/");
    expect(location).not.toMatch(/^https?:\/\//);
  });

  it("keeps the query string", () => {
    expect(redirectTo("/login?error=invalid").headers.get("location")).toBe("/login?error=invalid");
  });

  it("defaults to 303, the status a POST should redirect with", () => {
    // 303 makes the browser follow with GET. A 307 would repeat the POST at the
    // new location, which for the login handler would mean re-submitting the
    // password to the page it just redirected to.
    expect(redirectTo("/").status).toBe(303);
    expect(redirectTo("/", 307).status).toBe(307);
  });

  it("sets no body", async () => {
    expect(await redirectTo("/").text()).toBe("");
  });
});
