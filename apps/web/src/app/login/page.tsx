import { ShieldIcon } from "lucide-react";
import { dashboardPasswordConfigured } from "@/lib/session";

export const dynamic = "force-dynamic";

const MESSAGES: Record<string, string> = {
  invalid: "That password was not accepted.",
  unconfigured:
    "No dashboard password is configured. Set SECUREOPS_DASHBOARD_PASSWORD on the web service — an unset password is refused rather than treated as open access.",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const error = typeof params.error === "string" ? MESSAGES[params.error] : undefined;
  const configured = dashboardPasswordConfigured();

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
            type="password"
            name="password"
            autoFocus
            required
            autoComplete="current-password"
            placeholder="Dashboard password"
            aria-label="Dashboard password"
            className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none"
          />
          <button
            type="submit"
            disabled={!configured}
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

        {/* Stated rather than implied: one shared password is not a user model,
            and a reader should not infer more protection than exists. */}
        <p className="mt-6 text-center text-[11px] leading-relaxed text-ink-faint">
          One shared password. It controls access, not identity — actions are
          recorded against the dashboard until per-user identity lands.
        </p>
      </div>
    </div>
  );
}
