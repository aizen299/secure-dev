/**
 * The session cookie's name, and nothing else.
 *
 * Its own module because the middleware runs on the edge runtime, which has no
 * node:crypto -- importing it from session.ts would drag the HMAC code into a
 * runtime that cannot load it. Keeping the constant separate is also the
 * honest split: the name is shared, the verification is not.
 */
export const SESSION_COOKIE = "secureops_session";
