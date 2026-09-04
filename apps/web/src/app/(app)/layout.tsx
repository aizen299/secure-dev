import { AppShell } from "@/components/shell/app-shell";
import { requireSession } from "@/lib/guard";
import { whoAmI, tolerant, redirectIfSessionExpired, ApiError } from "@/lib/api";

/**
 * The signed-in frame.
 *
 * A route group, so the login page renders without a sidebar around it -- a
 * shell offering navigation into pages you cannot reach is a worse first
 * impression than a plain form.
 *
 * The session is verified HERE rather than relying on the middleware. The
 * middleware runs on the edge runtime, which has no node:crypto, so it can
 * only test that a cookie exists; a forged cookie would pass it. Every page
 * under this layout is checked properly, server-side, on every request.
 */
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  await requireSession();

  // Who is signed in, for the sidebar. Best-effort: an unreachable API must not
  // take down the frame, and the pages inside it report that state themselves
  // with more to say about it than a shell can.
  //
  // What this identity does NOT do is authorise anything. It decides which
  // links are worth showing; the API refuses the rest regardless, which is why
  // /users renders its own "administrators only" state rather than trusting
  // this to have hidden the link.
  //
  // A 401 is the exception: `requireSession` above only checks the cookie's
  // SHAPE, because verifying it is the API's job. So a session that has aged
  // out, or belongs to an account since disabled, gets past that check and
  // fails here -- and the honest response is the login form, not a frame
  // around pages that will each report an outage that is not happening.
  const me = await tolerant(async () => {
    try {
      return await whoAmI();
    } catch (error) {
      if (error instanceof ApiError) redirectIfSessionExpired(error);
      throw error;
    }
  });

  return (
    <AppShell identity={me}>{children}</AppShell>
  );
}
