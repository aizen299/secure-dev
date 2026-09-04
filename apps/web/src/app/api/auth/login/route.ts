import { NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_MAX_AGE_SECONDS,
  dashboardPasswordConfigured,
  issueSession,
  passwordMatches,
} from "@/lib/session";

/** A deliberate delay on every attempt, correct or not.
 *
 *  Not a rate limiter -- it is one shared password behind a login form, and
 *  making each guess cost something is the cheapest useful defence against
 *  someone working through a list. Applied uniformly so the delay itself
 *  reveals nothing. */
const ATTEMPT_DELAY_MS = 400;

export async function POST(request: Request) {
  const body = await request.formData().catch(() => null);
  const password = String(body?.get("password") ?? "");

  await new Promise((resolve) => setTimeout(resolve, ATTEMPT_DELAY_MS));

  if (!dashboardPasswordConfigured()) {
    // An unset password never means "let everyone in".
    return NextResponse.redirect(new URL("/login?error=unconfigured", request.url), 303);
  }
  if (!passwordMatches(password)) {
    return NextResponse.redirect(new URL("/login?error=invalid", request.url), 303);
  }

  const response = NextResponse.redirect(new URL("/", request.url), 303);
  response.cookies.set(SESSION_COOKIE, issueSession(), {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
  return response;
}
