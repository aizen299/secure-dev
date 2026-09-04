import "server-only";

/**
 * Refuses to start when a removed setting is still configured.
 *
 * `SECUREOPS_DASHBOARD_PASSWORD` was ADR 029's shared password. It is gone
 * (ADR 033 §6a): a session minted from it had no identity behind it, so the
 * audit trail still said "the dashboard" — the residue T-57 and T-59 describe,
 * and the whole reason people exist now.
 *
 * Refusing rather than ignoring, because ignoring is the dangerous half. An
 * operator with that variable still set would believe a credential works, and
 * would find out otherwise from somebody unable to sign in. The same refusal
 * SECUREOPS_API_TOKENS makes for its old formats (ADR 006, ADR 023, ADR 033).
 */
const REMOVED: Record<string, string> = {
  SECUREOPS_DASHBOARD_PASSWORD:
    "the shared dashboard password was removed in ADR 033. Create an account instead: " +
    "useradd -email you@example.com -role admin",
};

export function assertNoRemovedSettings(
  env: Record<string, string | undefined> = process.env,
): void {
  const found = Object.keys(REMOVED).filter((key) => (env[key] ?? "").trim() !== "");
  if (found.length === 0) return;

  throw new Error(
    "SecureOps dashboard: removed settings are still configured.\n" +
      found.map((key) => `  ${key}: ${REMOVED[key]}`).join("\n"),
  );
}
