import { NextResponse } from "next/server";

/**
 * A redirect to a path on this same origin.
 *
 * `NextResponse.redirect(new URL(path, request.url))` builds an absolute URL
 * from the request as the *server* saw it. Behind Docker or any proxy that is
 * the container's own hostname, so a browser that posted to
 * `localhost:3000/api/auth/login` was being sent to
 * `http://d000a8fee022:3000/` — a host it cannot resolve. Login appeared to do
 * nothing.
 *
 * The obvious repair is to rebuild the URL from the `Host` or
 * `X-Forwarded-Host` header, which means trusting a client-supplied header to
 * decide where to send a browser carrying a fresh session cookie. A relative
 * `Location` avoids the question: RFC 7231 permits it, every browser resolves
 * it against the address bar, and there is no header to trust.
 */
export function redirectTo(path: `/${string}`, status: 303 | 307 = 303): NextResponse {
  return new NextResponse(null, { status, headers: { Location: path } });
}
