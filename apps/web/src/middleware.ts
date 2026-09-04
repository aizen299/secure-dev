import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * Everything requires a session except the login page and what it needs.
 *
 * A deny-by-default matcher rather than a list of protected routes: a page
 * added later is protected by existing, not by somebody remembering to add it
 * (the same reasoning the API's route group uses).
 *
 * The cookie's signature is NOT verified here. Middleware runs on the edge
 * runtime, which has no node:crypto, and a partial check here would invite the
 * belief that this is the security boundary. It is a redirect for the common
 * case; every route handler and page verifies the session properly server-side.
 */
export function middleware(request: NextRequest) {
  if (request.cookies.get(SESSION_COOKIE)) return NextResponse.next();

  const url = request.nextUrl.clone();
  url.pathname = "/login";
  url.search = "";
  return NextResponse.redirect(url);
}

export const config = {
  matcher: [
    // Everything except the login page, the auth endpoints, Next's own
    // assets, and the icons.
    //
    // The icons are excluded because the login page needs them too, and a tab
    // icon behind a login is a missing tab icon. Nothing about a logo is
    // sensitive; the pages it decorates are what this gate is for.
    "/((?!login|api/auth|_next/static|_next/image|favicon.ico|icon.svg|apple-icon).*)",
  ],
};
