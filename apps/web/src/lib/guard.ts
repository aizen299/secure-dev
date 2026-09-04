import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { SESSION_COOKIE, sessionLooksValid } from "./session";

/**
 * The session token for the current request, or undefined.
 *
 * This is what the API client sends in place of the dashboard's own credential,
 * so a person's role and project scope apply to every read (ADR 033 §5a).
 * Without it a viewer would see the whole estate through the dashboard's
 * service token, and the audit trail would still name the dashboard.
 */
export async function sessionToken(): Promise<string | undefined> {
  const value = (await cookies()).get(SESSION_COOKIE)?.value;
  return sessionLooksValid(value) ? value : undefined;
}

/**
 * Redirects to the login page when there is no usable session.
 *
 * A shape check only. The API decides whether a session is real, and it
 * re-reads the user on every request -- so a disabled account is refused there
 * even while this cookie still looks fine. A page that gets a 401 from the API
 * renders its unreachable state, which is the honest outcome: "the API refused
 * this" and "you are not signed in" are different facts.
 */
export async function requireSession(): Promise<void> {
  if (!(await sessionToken())) redirect("/login");
}

/** The same check for route handlers, which answer rather than redirect. */
export async function hasSession(): Promise<boolean> {
  return (await sessionToken()) !== undefined;
}
