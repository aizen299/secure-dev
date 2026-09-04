import Link from "next/link";
import { ArchiveIcon, FolderOpenIcon, PlugZapIcon } from "lucide-react";
import {
  listProjects,
  getProjectRisk,
  listProjectScans,
  optional,
  MissingCredentialError,
  ApiError,
  redirectIfSessionExpired,
  collect,
  MAX_PAGE,
  type Project,
  type Risk,
  type Scan,
} from "@/lib/api";
import { PageHeader, PageBody } from "@/components/shell/page-header";
import { SetupNotice } from "@/components/shell/setup-notice";
import { EmptyState } from "@/components/security/empty";
import { RelativeTime } from "@/components/security/relative-time";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

interface Row {
  project: Project;
  risk: Risk | null;
  /** The most recent scan, if any. Deliberately separate from `risk`: a
   *  project can be scanned and not scored -- findings are persisted before
   *  the score is derived, and a worker that failed to score still ran. */
  lastScan: Scan | null;
}

function scoreTone(score: number) {
  if (score >= 75) return "text-critical";
  if (score >= 50) return "text-high";
  if (score >= 25) return "text-medium";
  if (score > 0) return "text-low";
  return "text-pass";
}

type LoadResult =
  | { ok: true; rows: Row[]; truncated: boolean }
  | { ok: false; reason: "unconfigured" | "unreachable"; forbidden: boolean };

/** Pages of projects read before the list is declared partial. 100 per page. */
const MAX_PROJECT_PAGES = 20;

/**
 * Loads every project with its risk.
 *
 * The awaits are inside the try and the JSX is not: a try/catch around
 * returned JSX catches nothing that happens while React renders it, so writing
 * it that way would look like error handling while handling nothing.
 */
async function load(archived: boolean): Promise<LoadResult> {
  try {
    // Every page, not the first one. The API orders projects by creation date,
    // and this list is sorted by risk -- so fetching a single page would sort
    // an arbitrary subset and could hide the highest-risk project entirely.
    // For a view whose whole purpose is "show me the worst thing", that is not
    // a cosmetic limit.
    const { items: data, truncated } = await collect<Project>(
      async (limit, offset) => {
        const page = await listProjects({ limit, offset, archived });
        return { items: page.data, hasMore: page.pagination.has_more };
      },
      MAX_PROJECT_PAGES,
    );

    // One risk call per project. Worth it: a project list without risk is a
    // list of names, which answers nothing an operator actually asks. Past a
    // few thousand projects the fix is a summary endpoint on the API, not a
    // slower page.
    const rows = await Promise.all(
      data.map(async (project) => ({
        project,
        risk: await optional(() => getProjectRisk(project.id)),
        lastScan: await optional(async () => {
          const page = await listProjectScans(project.id, { limit: 1 });
          return page.data[0] ?? null;
        }),
      })),
    );
    return { ok: true, rows, truncated };
  } catch (error) {
    if (error instanceof MissingCredentialError) {
      return { ok: false, reason: "unconfigured", forbidden: false };
    }
    // A dead session is not an outage. Handled first, and by leaving: the page
    // has nothing useful to render for somebody who needs to sign in again.
    redirectIfSessionExpired(error);
    return {
      ok: false,
      reason: "unreachable",
      // What remains is a 403: signed in, and not permitted to list projects.
      forbidden: error instanceof ApiError && error.isForbidden,
    };
  }
}

export default async function ProjectsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  // Archived projects are a separate view, not a filter layered onto this one.
  // They accept no new scans, so listing them beside live projects would put a
  // project you cannot act on in a list read to decide what to act on.
  const archived = (await searchParams).archived === "1";
  const result = await load(archived);

  if (!result.ok && result.reason === "unconfigured") {
    return (
      <>
        <PageHeader title="Projects" />
        <PageBody>
          <SetupNotice />
        </PageBody>
      </>
    );
  }

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Projects" />
        <PageBody>
          <Card>
            <EmptyState
              icon={<PlugZapIcon className="size-4" />}
              tone="warn"
              title={result.forbidden ? "Not yours to see" : "The API is unreachable"}
              description={
                result.forbidden
                  ? "Your account is not a member of any project. An administrator grants access on the Access screen."
                  : "Nothing can be read right now. This is not the same as having no findings."
              }
            />
          </Card>
        </PageBody>
      </>
    );
  }

  const { rows, truncated } = result;

  const scanned = rows.filter((r) => r.lastScan !== null).length;
  const unscored = rows.filter((r) => r.lastScan !== null && r.risk === null).length;

  return (
    <>
      <PageHeader
        title={archived ? "Archived projects" : "Projects"}
        actions={
          <div className="flex items-center gap-3">
            <span className="text-[12px] tabular-nums text-ink-faint">
              {rows.length} {rows.length === 1 ? "project" : "projects"}
              {!archived && scanned < rows.length && ` · ${rows.length - scanned} never scanned`}
              {!archived && unscored > 0 && ` · ${unscored} scanned but not scored`}
            </span>
            {/* The way back to an archived project. Without this, archiving one
                removed it from the only list that names it, and the control
                that restores it lives on its page -- so archive was reversible
                in the API and one-way in the UI. */}
            <Link
              href={archived ? "/projects" : "/projects?archived=1"}
              className="inline-flex h-7 items-center gap-1.5 rounded-md border border-line-strong px-2.5 text-[12px] text-ink-muted transition-colors duration-150 hover:bg-raised hover:text-ink"
            >
              <ArchiveIcon className="size-3" />
              {archived ? "Back to active" : "Archived"}
            </Link>
          </div>
        }
      />

      <PageBody>
        {rows.length === 0 ? (
          <Card>
            <EmptyState
              icon={
                archived ? (
                  <ArchiveIcon className="size-4" />
                ) : (
                  <FolderOpenIcon className="size-4" />
                )
              }
              title={archived ? "Nothing archived" : "No projects yet"}
              description={
                archived
                  ? "Archiving a project hides it from the active list and stops it accepting new scans. Everything already gathered about it stays readable, and it can be restored from its own page."
                  : "Paste a repository or website URL on the overview to scan one. Projects appear here as soon as they exist — a project with no scans is still a project."
              }
            />
          </Card>
        ) : (
          <Card className="overflow-hidden">
            <div className="grid grid-cols-[minmax(0,1fr)_96px_88px_104px] items-center gap-x-4 border-b border-line px-4 py-2">
              <span className="eyebrow">Project</span>
              <span className="eyebrow flex justify-end pr-3">Risk</span>
              <span className="eyebrow text-right">Findings</span>
              <span className="eyebrow text-right">Last scan</span>
            </div>

            {rows
              // Worst first. A project list read top-down should put the thing
              // that needs attention at the top; alphabetical ordering would
              // hide it behind a name.
              .sort((a, b) => (b.risk?.score ?? -1) - (a.risk?.score ?? -1))
              .map(({ project, risk, lastScan }) => (
                <Link
                  key={project.id}
                  href={`/projects/${project.id}`}
                  className={cn(
                    "grid grid-cols-[minmax(0,1fr)_96px_88px_104px] items-center gap-x-4 border-b border-line px-4 py-3 last:border-b-0",
                    "transition-colors duration-75 hover:bg-raised/50",
                  )}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-[13px] font-medium text-ink">
                        {project.name}
                      </span>
                      {project.environment === "production" && (
                        <Badge variant="outline">prod</Badge>
                      )}
                      {project.internet_facing && <Badge variant="outline">internet-facing</Badge>}
                    </div>
                    <p className="mt-0.5 truncate font-mono text-[11px] text-ink-faint">
                      {project.slug}
                    </p>
                  </div>

                  {/* The coverage dot gets its own fixed slot rather than
                      sitting inline. Inline, it shifted the number left on
                      exactly the rows that have it, so a column of scores
                      stopped lining up on the decimal point -- which is the
                      one thing a column of scores is for. */}
                  <div className="flex items-center justify-end gap-1.5">
                    {risk ? (
                      <>
                        <span
                          className={cn(
                            "text-[15px] font-medium tabular-nums",
                            scoreTone(risk.score),
                          )}
                        >
                          {risk.score.toFixed(1)}
                        </span>
                        <span className="w-1.5 shrink-0">
                          {!risk.complete && (
                            <span
                              className="block size-1.5 rounded-full bg-warn"
                              title="Computed from a scan with degraded coverage"
                            />
                          )}
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="text-[13px] text-ink-faint">—</span>
                        <span className="w-1.5 shrink-0" />
                      </>
                    )}
                  </div>

                  <div className="text-right text-[13px] tabular-nums text-ink-muted">
                    {risk ? risk.live_findings : <span className="text-ink-faint">—</span>}
                  </div>

                  {/* Read from the scans, not from the risk score. A project
                      can be scanned and not scored -- findings are persisted
                      before the score is derived -- and reporting that as
                      "never scanned" would state something plainly untrue
                      about a project that has findings sitting in it. */}
                  <div className="text-right text-[12px] text-ink-faint">
                    {lastScan ? (
                      <RelativeTime value={lastScan.queued_at} />
                    ) : (
                      "never scanned"
                    )}
                  </div>
                </Link>
              ))}
          </Card>
        )}

        {truncated && (
          <p className="mt-3 text-[11px] text-ink-faint">
            Showing the first {MAX_PROJECT_PAGES * MAX_PAGE} projects. The risk
            ordering below covers only those.
          </p>
        )}
      </PageBody>
    </>
  );
}
