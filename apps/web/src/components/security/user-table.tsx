"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { CheckIcon, LoaderIcon, PlusIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { User, UserRole, Project } from "@/lib/api";
import { RelativeTime } from "./relative-time";

const ROLES: { value: UserRole; label: string; can: string }[] = [
  { value: "viewer", label: "Viewer", can: "Reads the projects they are a member of" },
  { value: "engineer", label: "Engineer", can: "Triages findings and submits scans" },
  { value: "admin", label: "Admin", can: "Manages accounts and policy, reaches every project" },
];

/**
 * The operator roster, and the controls that change it.
 *
 * Every mutation goes to the API and the API decides. The dashboard does not
 * check the role itself — a second copy of that rule would be a place for the
 * two to disagree — so a refusal arrives as a message rather than as a button
 * that was never shown.
 *
 * That includes the last-administrator guard: demoting or disabling the only
 * enabled admin returns a 409 whose message says to appoint another one first.
 * Hiding the control would be worse, because it would leave the reason unsaid.
 */
export function UserTable({ users, projects }: { users: User[]; projects: Project[] }) {
  const router = useRouter();
  const [busy, setBusy] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);

  const projectName = React.useMemo(
    () => new Map(projects.map((p) => [p.id, p.name])),
    [projects],
  );

  async function patch(id: string, changes: Record<string, unknown>) {
    setBusy(id);
    setError(null);
    try {
      const response = await fetch(`/api/users/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(changes),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error?: string };
        setError(body.error ?? "The change was not accepted.");
        return;
      }
      router.refresh();
    } catch {
      setError("The dashboard could not reach its API.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <span className="eyebrow">People</span>
        <button
          type="button"
          onClick={() => setCreating((open) => !open)}
          className={cn(
            "inline-flex h-8 items-center gap-1.5 rounded-md border border-line-strong px-2.5",
            "text-[12px] font-medium text-ink transition-colors duration-150 hover:bg-raised",
          )}
        >
          <PlusIcon className="size-3.5" />
          {creating ? "Cancel" : "Add someone"}
        </button>
      </div>

      {creating && <CreateForm onDone={() => { setCreating(false); router.refresh(); }} onError={setError} />}

      {error && (
        <p role="alert" className="animate-in rounded-md border border-fail/25 bg-fail-dim px-3 py-2 text-[12px] leading-relaxed text-fail">
          {error}
        </p>
      )}

      <div className="overflow-x-auto rounded-lg border border-line bg-panel">
        <table className="w-full min-w-[720px] text-[13px]">
          <thead>
            <tr className="border-b border-line">
              {["Person", "Role", "Projects", "Last seen", ""].map((h) => (
                <th key={h} className="eyebrow px-4 py-2.5 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className="border-b border-line last:border-b-0">
                <td className="px-4 py-3">
                  <div className={cn("text-ink", user.disabled && "text-ink-faint line-through")}>
                    {user.display_name || user.email}
                  </div>
                  {user.display_name && (
                    <div className="mt-0.5 font-mono text-[11px] text-ink-faint">{user.email}</div>
                  )}
                </td>

                <td className="px-4 py-3">
                  <select
                    aria-label={`Role for ${user.email}`}
                    value={user.role}
                    disabled={busy === user.id}
                    onChange={(e) => patch(user.id, { role: e.target.value })}
                    className="h-7 rounded-md border border-line-strong bg-surface px-2 text-[12px] text-ink disabled:opacity-40"
                  >
                    {ROLES.map((r) => (
                      <option key={r.value} value={r.value} title={r.can}>{r.label}</option>
                    ))}
                  </select>
                </td>

                <td className="px-4 py-3 text-[12px] text-ink-muted">
                  {user.role === "admin" ? (
                    // Stated rather than shown as an empty list: an admin's
                    // reach comes from the role, so editing membership for one
                    // would change nothing and imply otherwise.
                    <span className="text-ink-faint">Every project, from the role</span>
                  ) : user.projects.length === 0 ? (
                    <span className="text-warn">None — sees nothing</span>
                  ) : (
                    user.projects.map((id) => projectName.get(id) ?? id).join(", ")
                  )}
                </td>

                <td className="px-4 py-3 text-[12px] text-ink-faint">
                  {user.last_login_at ? <RelativeTime value={user.last_login_at} /> : "Never"}
                </td>

                <td className="px-4 py-3 text-right">
                  <button
                    type="button"
                    disabled={busy === user.id}
                    onClick={() => patch(user.id, { disabled: !user.disabled })}
                    className={cn(
                      "inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-[12px]",
                      "transition-colors duration-150 disabled:opacity-40",
                      // Quiet until reached for. Disabling is significant but
                      // routine and reversible, and a column of red buttons
                      // spends the alarm colour on a list rather than on the
                      // one row that needs it.
                      user.disabled
                        ? "border-accent/40 text-accent hover:bg-accent/10"
                        : "border-line-strong text-ink-muted hover:border-fail/40 hover:bg-fail-dim hover:text-fail",
                    )}
                  >
                    {busy === user.id && <LoaderIcon className="size-3 animate-spin" />}
                    {user.disabled ? "Enable" : "Disable"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        Disabling takes effect on the next request, not at the next sign-in — the
        session is checked against the account every time. An account is never
        deleted; its actions stay in the audit trail under its name.
      </p>

      {/* Membership is not editable here yet, and saying so is better than a
          control that silently does nothing. */}
      <p className="text-[11px] leading-relaxed text-ink-faint">
        Project membership is set through the API for now:{" "}
        <code className="rounded bg-raised px-1 py-0.5 font-mono text-[11px]">
          PATCH /api/v1/users/&#123;id&#125; &#123;&quot;projects&quot;: [&quot;&hellip;&quot;]&#125;
        </code>
      </p>
    </div>
  );
}

function CreateForm({ onDone, onError }: { onDone: () => void; onError: (message: string) => void }) {
  const [busy, setBusy] = React.useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    onError("");

    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: String(form.get("email") ?? ""),
          password: String(form.get("password") ?? ""),
          display_name: String(form.get("display_name") ?? ""),
          role: String(form.get("role") ?? "viewer"),
        }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error?: string };
        onError(body.error ?? "The account could not be created.");
        return;
      }
      onDone();
    } catch {
      onError("The dashboard could not reach its API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-2 rounded-lg border border-line bg-panel p-4 sm:grid-cols-2">
      <input name="email" type="email" required placeholder="Email" aria-label="Email"
        className="h-9 rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none" />
      <input name="display_name" placeholder="Name (optional)" aria-label="Display name"
        className="h-9 rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none" />
      <input name="password" type="password" required minLength={12} placeholder="Password — 12 characters or more"
        aria-label="Password" autoComplete="new-password"
        className="h-9 rounded-md border border-line-strong bg-surface px-3 text-[13px] text-ink placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none" />
      <div className="flex gap-2">
        <select name="role" defaultValue="viewer" aria-label="Role"
          className="h-9 flex-1 rounded-md border border-line-strong bg-surface px-2 text-[13px] text-ink">
          {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
        </select>
        <button type="submit" disabled={busy}
          className="inline-flex h-9 items-center gap-1.5 rounded-md bg-ink px-3.5 text-[13px] font-medium text-inverse transition-colors duration-150 hover:bg-ink/90 disabled:opacity-40">
          {busy ? <LoaderIcon className="size-3.5 animate-spin" /> : <CheckIcon className="size-3.5" />}
          Create
        </button>
      </div>
      <p className="text-[11px] leading-relaxed text-ink-faint sm:col-span-2">
        Twelve characters minimum, and no composition rules — length is what
        resists an offline attack on a stolen hash. The password is hashed with
        Argon2id before it reaches the database and is never shown again.
      </p>
    </form>
  );
}
