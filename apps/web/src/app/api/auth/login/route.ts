import { SESSION_COOKIE, SESSION_MAX_AGE_SECONDS } from "@/lib/session";
import { redirectTo } from "@/lib/redirect";
import { login } from "@/lib/api";

/**
 * Signs a person in (ADR 033).
 *
 * The dashboard no longer decides this. It forwards the credentials to the API,
 * which owns the users and answers with a session token; the cookie is just
 * where that token is kept.
 *
 * There is no uniform delay here any more, and no timing defence: both live in
 * the API's login handler, which is where the comparison actually happens. A
 * second delay in front of it would add latency without adding a control.
 */
export async function POST(request: Request) {
  const body = await request.formData().catch(() => null);
  const email = String(body?.get("email") ?? "");
  const password = String(body?.get("password") ?? "");

  const result = await login(email, password);

  if (!result.ok) {
    // One answer for every cause, matching what the API returns. The dashboard
    // must not narrow it: "no such account" would tell somebody which
    // addresses are registered, which is exactly what the API refuses to say.
    return redirectTo(`/login?error=${result.reason}`);
  }

  const response = redirectTo("/");
  response.cookies.set(SESSION_COOKIE, result.token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
  return response;
}
