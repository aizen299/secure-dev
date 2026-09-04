import { ShieldOffIcon, PlugZapIcon } from "lucide-react";
import {
  listUsers,
  listProjects,
  whoAmI,
  tolerant,
  MissingCredentialError,
  ApiError,
  collect,
  redirectIfSessionExpired,
  type User,
  type Project,
  type Identity,
} from "@/lib/api";
import { requireSession } from "@/lib/guard";
import { PageHeader, PageBody } from "@/components/shell/page-header";
import { SetupNotice } from "@/components/shell/setup-notice";
import { EmptyState } from "@/components/security/empty";
import { UserTable } from "@/components/security/user-table";
import { Card } from "@/components/ui/card";

export const dynamic = "force-dynamic";

/** Pages of projects read before the name lookup is declared partial. */
const MAX_PROJECT_PAGES = 20;

type LoadResult =
  | { ok: true; users: User[]; projects: Project[]; me: Identity | null }
  | { ok: false; reason: "unconfigured" | "forbidden" | "unreachable" };

/**
 * Reads the roster with the signed-in person's own session.
 *
 * A 403 here is a correct answer, not a failure: the API refuses the roster to
 * anyone who is not an administrator, and this page reports that refusal rather
 * than dressing it up as a broken connection.
 */
async function load(): Promise<LoadResult> {
  try {
    const [users, me] = await Promise.all([listUsers(), tolerant(() => whoAmI())]);

    // Names for the membership column. Best-effort: a failure here costs
    // readable project names, not the page, so it must not take the roster down
    // with it.
    const projects =
      (await tolerant(async () => {
        const { items } = await collect<Project>(async (limit, offset) => {
          const page = await listProjects({ limit, offset });
          return { items: page.data, hasMore: page.pagination.has_more };
        }, MAX_PROJECT_PAGES);
        return items;
      })) ?? [];

    return { ok: true, users: users.data, projects, me };
  } catch (error) {
    if (error instanceof MissingCredentialError) {
      return { ok: false, reason: "unconfigured" };
    }
    // Sign in again, rather than a page reporting an outage that is not
    // happening. Before the 403 check, because a dead session cannot be
    // anything else.
    redirectIfSessionExpired(error);
    if (error instanceof ApiError && error.isForbidden) {
      return { ok: false, reason: "forbidden" };
    }
    return { ok: false, reason: "unreachable" };
  }
}

export default async function UsersPage() {
  await requireSession();
  const result = await load();

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Access" />
        <PageBody>
          {result.reason === "unconfigured" ? (
            <SetupNotice />
          ) : (
            <Card>
              <EmptyState
                icon={
                  result.reason === "forbidden" ? (
                    <ShieldOffIcon className="size-4" />
                  ) : (
                    <PlugZapIcon className="size-4" />
                  )
                }
                tone="warn"
                title={
                  result.reason === "forbidden"
                    ? "Administrators only"
                    : "The API is unreachable"
                }
                description={
                  result.reason === "forbidden"
                    ? "Managing accounts needs the admin role. Everything else in the dashboard stays available to you."
                    : "The roster cannot be read right now. This is not the same as there being no accounts."
                }
              />
            </Card>
          )}
        </PageBody>
      </>
    );
  }

  const { users, projects, me } = result;
  const admins = users.filter((u) => u.role === "admin" && !u.disabled).length;
  const disabled = users.filter((u) => u.disabled).length;

  return (
    <>
      <PageHeader
        title="Access"
        actions={
          <span className="text-[12px] tabular-nums text-ink-faint">
            {users.length} {users.length === 1 ? "account" : "accounts"}
            {` · ${admins} ${admins === 1 ? "admin" : "admins"}`}
            {disabled > 0 && ` · ${disabled} disabled`}
          </span>
        }
      />

      <PageBody>
        <div className="space-y-4">
          {/* The one number worth calling out. A deployment with a single
              enabled admin is one lockout away from needing SQL to recover,
              and the store's guard prevents the last one being removed rather
              than making that situation safe. */}
          {admins === 1 && (
            <p className="rounded-md border border-warn/25 bg-warn-dim px-3 py-2 text-[12px] leading-relaxed text-warn">
              One enabled administrator. The API refuses to remove the last one,
              so losing this password means recovering through the database —
              appoint a second admin.
            </p>
          )}

          <UserTable users={users} projects={projects} />

          {me?.user_id && (
            <p className="text-[11px] leading-relaxed text-ink-faint">
              Signed in as {me.label} ({me.role}). Changes made here are audited
              against your account, not the dashboard&apos;s credential.
            </p>
          )}
        </div>
      </PageBody>
    </>
  );
}
