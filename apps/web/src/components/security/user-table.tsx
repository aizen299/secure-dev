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
  const [editing, setEditing] = React.useState<string | null>(null);

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
              <React.Fragment key={user.id}>
              <tr className={cn("border-b border-line", editing !== user.id && "last:border-b-0")}>
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
                    // Stated rather than shown as an editable list: an admin's
                    // reach comes from the role, so granting membership would
                    // change nothing and imply otherwise.
                    <span className="text-ink-faint">Every project, from the role</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setEditing(editing === user.id ? null : user.id)}
                      aria-expanded={editing === user.id}
                      className={cn(
                        "-mx-1 rounded px-1 py-0.5 text-left transition-colors duration-150",
                        "hover:bg-raised hover:text-ink",
                        user.projects.length === 0 && "text-warn",
                      )}
                    >
                      {user.projects.length === 0
                        ? "None — sees nothing"
                        : user.projects.map((id) => projectName.get(id) ?? id).join(", ")}
                    </button>
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

              {editing === user.id && user.role !== "admin" && (
                <tr className="border-b border-line last:border-b-0 bg-raised/30">
                  <td colSpan={5} className="px-4 py-3">
                    <MembershipEditor
                      user={user}
                      projects={projects}
                      busy={busy === user.id}
                      onCancel={() => setEditing(null)}
                      onSave={async (ids) => {
                        await patch(user.id, { projects: ids });
                        setEditing(null);
                      }}
                    />
                  </td>
                </tr>
              )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        Disabling takes effect on the next request, not at the next sign-in — the
        session is checked against the account every time. An account is never
        deleted; its actions stay in the audit trail under its name.
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

/**
 * Grants and revokes a person's project membership.
 *
 * The API replaces the whole set rather than merging into it, so this submits
 * every box that is ticked, not a diff. That is why archived projects appear
 * here at all: leaving them out would mean a save that never mentioned one
 * silently revoked it.
 *
 * Membership is what a viewer and an engineer can reach. An admin does not
 * appear here -- their reach is the role, and a grant would imply otherwise.
 */
function MembershipEditor({
  user,
  projects,
  busy,
  onSave,
  onCancel,
}: {
  user: User;
  projects: Project[];
  busy: boolean;
  onSave: (projectIds: string[]) => void | Promise<void>;
  onCancel: () => void;
}) {
  const [selected, setSelected] = React.useState<Set<string>>(
    () => new Set(user.projects),
  );

  // Live first, then archived, each alphabetical. An archived project is still
  // grantable -- its history stays readable -- but it is not what somebody is
  // usually looking for, so it sorts below.
  const ordered = React.useMemo(
    () =>
      [...projects].sort(
        (a, b) =>
          Number(a.archived) - Number(b.archived) || a.name.localeCompare(b.name),
      ),
    [projects],
  );

  const changed =
    selected.size !== user.projects.length ||
    user.projects.some((id) => !selected.has(id));

  if (projects.length === 0) {
    return (
      <p className="text-[12px] text-ink-faint">
        There are no projects to grant yet.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-[11px] text-ink-faint">
        {user.display_name || user.email} reads and acts on the projects ticked
        here, and nothing else.
      </p>

      <div className="grid max-h-56 gap-x-4 gap-y-1.5 overflow-y-auto sm:grid-cols-2 lg:grid-cols-3">
        {ordered.map((project) => (
          <label
            key={project.id}
            className="flex cursor-pointer items-center gap-2 text-[12px] text-ink-muted hover:text-ink"
          >
            <input
              type="checkbox"
              checked={selected.has(project.id)}
              disabled={busy}
              onChange={(e) =>
                setSelected((current) => {
                  const next = new Set(current);
                  if (e.target.checked) next.add(project.id);
                  else next.delete(project.id);
                  return next;
                })
              }
              className="size-3.5 shrink-0 accent-accent"
            />
            <span className="truncate">{project.name}</span>
            {project.archived && (
              <span className="shrink-0 text-[10px] text-ink-faint">archived</span>
            )}
          </label>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={busy || !changed}
          onClick={() => onSave([...selected])}
          className="inline-flex h-7 items-center gap-1.5 rounded-md bg-ink px-3 text-[12px] font-medium text-inverse transition-colors duration-150 hover:bg-ink/90 disabled:opacity-40"
        >
          {busy ? <LoaderIcon className="size-3 animate-spin" /> : <CheckIcon className="size-3" />}
          Save
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="inline-flex h-7 items-center rounded-md border border-line-strong px-2.5 text-[12px] text-ink-muted transition-colors duration-150 hover:bg-raised hover:text-ink"
        >
          Cancel
        </button>
        <span className="text-[11px] text-ink-faint">
          {selected.size === 0
            ? "No projects — this account will see nothing."
            : `${selected.size} of ${projects.length}`}
        </span>
      </div>
    </div>
  );
}
