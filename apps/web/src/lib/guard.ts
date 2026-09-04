import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { SESSION_COOKIE, sessionIsValid } from "./session";

/**
 * The real session check, run in every page and route handler.
 *
 * Middleware only tests that a cookie exists, because the edge runtime has no
 * node:crypto to verify a signature with. This is where the signature and the
 * expiry are actually checked, which is why it runs server-side on every
 * request rather than once at the edge.
 */
export async function requireSession(): Promise<void> {
  const jar = await cookies();
  if (!sessionIsValid(jar.get(SESSION_COOKIE)?.value)) redirect("/login");
}

/** The same check for route handlers, which answer rather than redirect. */
export async function hasSession(): Promise<boolean> {
  const jar = await cookies();
  return sessionIsValid(jar.get(SESSION_COOKIE)?.value);
}
