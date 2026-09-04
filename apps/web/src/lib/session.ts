/**
 * Dashboard sessions.
 *
 * One shared password exchanged for a signed cookie (ADR 029). This answers
 * "may this browser look at this?" and deliberately not "who is looking?" --
 * per-user identity lives in the API and is Phase 11.
 *
 * Server-only. The signing key must never reach a browser, and the guard turns
 * a mistaken client import into a build error rather than a leak.
 */
import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export { SESSION_COOKIE } from "./session-cookie";

/** Eight hours: long enough for a working day, short enough that a forgotten
 *  tab on a shared machine stops being a way in. */
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

/**
 * The signing key.
 *
 * Generated per process when unset, which means a restart invalidates every
 * session. That is the right default for a security tool: the failure mode of
 * a missing key should be "everyone signs in again", never "sessions are
 * signed with a predictable value".
 */
const SESSION_KEY =
  process.env.SECUREOPS_DASHBOARD_SESSION_KEY?.trim() || randomBytes(32).toString("hex");

function sign(payload: string): string {
  return createHmac("sha256", SESSION_KEY).update(payload).digest("hex");
}

/** Compares two strings without leaking their contents through timing. */
function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  // timingSafeEqual throws on a length mismatch, which would itself be a
  // timing signal, so the lengths are folded into the comparison instead.
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

/** True when a password is configured at all. */
export function dashboardPasswordConfigured(): boolean {
  return (process.env.SECUREOPS_DASHBOARD_PASSWORD ?? "").trim().length > 0;
}

/**
 * Checks a submitted password.
 *
 * Returns false when none is configured. An unset password must never mean
 * "let everyone in" -- that is the permissive default ADR 006 refuses.
 */
export function passwordMatches(submitted: string): boolean {
  const expected = (process.env.SECUREOPS_DASHBOARD_PASSWORD ?? "").trim();
  if (expected === "") return false;
  return constantTimeEquals(submitted, expected);
}

/** Mints a session value: an expiry, signed. */
export function issueSession(now = Date.now()): string {
  const expires = String(now + SESSION_TTL_MS);
  return `${expires}.${sign(expires)}`;
}

/**
 * Validates a cookie value.
 *
 * The expiry is inside the signed payload rather than left to the cookie's own
 * Max-Age, because a browser is not a thing to take an expiry claim from.
 */
export function sessionIsValid(value: string | undefined, now = Date.now()): boolean {
  if (!value) return false;
  const [expires, signature] = value.split(".");
  if (!expires || !signature) return false;
  if (!constantTimeEquals(signature, sign(expires))) return false;

  const expiresAt = Number(expires);
  return Number.isFinite(expiresAt) && expiresAt > now;
}

export const SESSION_MAX_AGE_SECONDS = SESSION_TTL_MS / 1000;
