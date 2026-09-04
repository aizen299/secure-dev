import { ShieldIcon } from "lucide-react";

export const dynamic = "force-dynamic";

/**
 * One message for every rejected sign-in, deliberately.
 *
 * The API answers an unknown email, a wrong password, and a disabled account
 * identically, because distinguishing them tells somebody which addresses are
 * registered. Narrowing it here would give away what the API refuses to say
 * (ADR 033).
 */
const MESSAGES: Record<string, string> = {
  invalid: "The email or password is incorrect.",
  unconfigured:
    "No accounts exist yet. Create the first one on the server with: useradd -email you@example.com -role admin",
  unreachable: "The dashboard could not reach the API.",
  // Not a failure, and worded so it does not read as one. A session ages out
  // after eight hours, and it also ends the moment an administrator disables
  // the account -- so this must not promise that signing in will work.
  expired: "Your session has ended. Sign in again to continue.",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const error = typeof params.error === "string" ? MESSAGES[params.error] : undefined;

  return (
    <div className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-[320px]">
        <div className="mb-7 flex flex-col items-center gap-3 text-center">
          <div className="flex size-9 items-center justify-center rounded-lg bg-ink text-inverse">
            <ShieldIcon className="size-4.5" strokeWidth={2.5} />
          </div>
          <div>
            <h1 className="text-[15px] font-semibold tracking-tight text-ink">SecureOps</h1>
            <p className="mt-1 text-[12px] leading-relaxed text-ink-faint">
              One contextual security decision from fragmented scanner output.
            </p>
          </div>
        </div>

        <form method="POST" action="/api/auth/login" className="space-y-2.5">
          <input
            type="email"
            name="email"
            autoFocus
            required
            autoComplete="username"
            placeholder="Email"
            aria-label="Email"
            className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none"
          />
          <input
            type="password"
            name="password"
            required
            autoComplete="current-password"
            placeholder="Password"
            aria-label="Password"
            className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none"
          />
          <button
            type="submit"
            className="h-9 w-full rounded-md bg-ink text-[13px] font-medium text-inverse transition-colors duration-100 hover:bg-ink/90 disabled:opacity-40"
          >
            Sign in
          </button>
        </form>

        {error && (
          <p className="mt-3 rounded-md border border-fail/25 bg-fail-dim px-3 py-2 text-[12px] leading-relaxed text-fail">
            {error}
          </p>
        )}

        {/* Stated rather than implied, and now it is good news rather than a
            caveat: what you do here is recorded against you. */}
        <p className="mt-6 text-center text-[11px] leading-relaxed text-ink-faint">
          Your account decides what you can see and what you can change, and the
          audit trail records your actions under your name.
        </p>
      </div>
    </div>
  );
}
