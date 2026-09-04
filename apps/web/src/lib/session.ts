/**
 * Dashboard sessions.
 *
 * The cookie holds the API's own session token, and nothing else (ADR 033 §5a).
 *
 * ADR 029 had the dashboard mint an HMAC-signed cookie of its own, because
 * there were no users and the only question was "may this browser look at
 * this?". Now there are users, and the API issues a session that carries who
 * they are — so a second signed value would be a second answer to the same
 * question, and the two could disagree about whether somebody is still signed
 * in.
 *
 * So this file no longer signs anything. The API is the authority on whether a
 * session is valid, and it re-reads the user on every request — which is what
 * makes disabling an account take effect immediately rather than at the next
 * restart.
 *
 * Server-only. The token must never reach a browser as a readable value, and
 * the guard turns a mistaken client import into a build error rather than a
 * leak.
 */
import "server-only";

export { SESSION_COOKIE } from "./session-cookie";

/**
 * Eight hours, matching the API's own TTL exactly.
 *
 * The cookie expiring before or after the token would produce a session that is
 * valid to one layer and not the other — a sign-in that appears to work and
 * then 401s on the first read, or a cookie that survives a token nobody can
 * use.
 */
export const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;

/**
 * True when a value could be an API session.
 *
 * A shape check, not a validity check, and the distinction is the point: this
 * runs in the dashboard, which cannot verify the API's signature and must not
 * pretend to. It exists so an obviously empty or malformed cookie becomes a
 * redirect to the login page rather than a round trip that 401s.
 *
 * The API decides whether a session is real. Everything here is about not
 * wasting a request finding out.
 */
export function sessionLooksValid(value: string | undefined): boolean {
  if (!value) return false;
  // `usr_<id>.<expiry>.<hmac>` — the prefix the API routes on.
  return value.startsWith("usr_") && value.split(".").length >= 3;
}
