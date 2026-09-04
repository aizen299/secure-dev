import { AppShell } from "@/components/shell/app-shell";
import { requireSession } from "@/lib/guard";

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
  return <AppShell>{children}</AppShell>;
}
