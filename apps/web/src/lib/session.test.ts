/**
 * @vitest-environment node
 *
 * No DOM here: this module is `node:crypto` and environment variables. Running
 * it under jsdom would be slower and would test it in a context it never runs
 * in.
 */
import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The session boundary (ADR 029, ADR 031).
 *
 * These are the invariants the login rests on, and every one of them is
 * invisible from the outside: a cookie that fails any of them looks exactly
 * like a cookie that passes, right up until the server checks it.
 *
 * The module reads its key at import time, so each test re-imports it under a
 * fresh module registry rather than sharing one instance. Otherwise the first
 * test's key would silently decide every later test's result.
 */
async function load(env: Record<string, string | undefined>) {
  vi.resetModules();
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  return import("./session");
}

/**
 * Generated per run rather than written down.
 *
 * A literal 32-character hex string in a source file is indistinguishable from
 * a real signing key, and gitleaks flagged the first version of this file for
 * exactly that -- correctly. Allowlisting the line would have taught the
 * scanner to ignore a shape it should always question; generating the value
 * removes the shape. The tests do not depend on any particular key, only on
 * two of them differing.
 */
const key = () => randomBytes(16).toString("hex");
const KEY = key();

beforeEach(() => {
  delete process.env.SECUREOPS_DASHBOARD_PASSWORD;
  delete process.env.SECUREOPS_DASHBOARD_SESSION_KEY;
});

describe("passwordMatches", () => {
  it("accepts the configured password", async () => {
    const { passwordMatches } = await load({ SECUREOPS_DASHBOARD_PASSWORD: "correct horse" });
    expect(passwordMatches("correct horse")).toBe(true);
  });

  it("rejects a wrong password", async () => {
    const { passwordMatches } = await load({ SECUREOPS_DASHBOARD_PASSWORD: "correct horse" });
    expect(passwordMatches("correct hors")).toBe(false);
    expect(passwordMatches("correct horse ")).toBe(false);
    expect(passwordMatches("")).toBe(false);
  });

  // The permissive default ADR 006 refuses. An unset password must lock the
  // door, not remove it -- and the failure is silent either way, so it is
  // asserted rather than assumed.
  it("rejects everything when no password is configured", async () => {
    const { passwordMatches, dashboardPasswordConfigured } = await load({
      SECUREOPS_DASHBOARD_PASSWORD: undefined,
    });
    expect(dashboardPasswordConfigured()).toBe(false);
    expect(passwordMatches("")).toBe(false);
    expect(passwordMatches("anything")).toBe(false);
  });

  it("treats a whitespace-only password as unconfigured", async () => {
    const { passwordMatches, dashboardPasswordConfigured } = await load({
      SECUREOPS_DASHBOARD_PASSWORD: "   ",
    });
    expect(dashboardPasswordConfigured()).toBe(false);
    expect(passwordMatches("   ")).toBe(false);
  });
});

describe("sessionIsValid", () => {
  it("accepts a session it just issued", async () => {
    const { issueSession, sessionIsValid } = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    expect(sessionIsValid(issueSession())).toBe(true);
  });

  it("rejects a tampered signature", async () => {
    const { issueSession, sessionIsValid } = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    const [expires, signature] = issueSession().split(".");
    const flipped = signature!.startsWith("a")
      ? `b${signature!.slice(1)}`
      : `a${signature!.slice(1)}`;

    expect(sessionIsValid(`${expires}.${flipped}`)).toBe(false);
  });

  /**
   * The property that makes carrying the expiry inside the signature worth
   * doing, and the only place it is asserted.
   *
   * A cookie's own Max-Age is a claim the browser makes, and a browser is not a
   * thing to take an expiry claim from. If the expiry were outside the
   * signature, this rewrite would grant an indefinite session.
   */
  it("rejects an expiry rewritten to the far future", async () => {
    const { issueSession, sessionIsValid } = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    const signature = issueSession().split(".")[1];

    expect(sessionIsValid(`99999999999999.${signature}`)).toBe(false);
  });

  it("rejects a session past its expiry", async () => {
    const { issueSession, sessionIsValid } = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    const now = Date.now();
    const value = issueSession(now);

    expect(sessionIsValid(value, now + 60_000)).toBe(true);
    // Eight hours and a minute later.
    expect(sessionIsValid(value, now + 8 * 60 * 60 * 1000 + 60_000)).toBe(false);
  });

  it("rejects malformed and absent values", async () => {
    const { sessionIsValid } = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    for (const value of [undefined, "", ".", "nodot", "abc.", ".abc", "not-a-number.abc"]) {
      expect(sessionIsValid(value)).toBe(false);
    }
  });

  /**
   * A session signed with one key must not validate under another.
   *
   * This is what makes the per-process fallback key safe: with no
   * SECUREOPS_DASHBOARD_SESSION_KEY set, a restart mints a new key and every
   * outstanding session stops working. That is the intended behaviour, and it
   * only holds if the key actually participates in the signature.
   */
  it("rejects a session signed with a different key", async () => {
    const first = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: KEY });
    const value = first.issueSession();

    const second = await load({ SECUREOPS_DASHBOARD_SESSION_KEY: key() });
    expect(second.sessionIsValid(value)).toBe(false);
  });
});
