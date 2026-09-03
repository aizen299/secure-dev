import Link from "next/link";
import { FolderOpenIcon, PlugZapIcon } from "lucide-react";
import {
  listProjects,
  getProjectRisk,
  optional,
  MissingCredentialError,
  ApiError,
  collect,
  MAX_PAGE,
  type Project,
  type Risk,
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
  | { ok: false; reason: "unconfigured" | "unreachable"; unauthorized: boolean };

/** Pages of projects read before the list is declared partial. 100 per page. */
const MAX_PROJECT_PAGES = 20;

/**
 * Loads every project with its risk.
 *
 * The awaits are inside the try and the JSX is not: a try/catch around
 * returned JSX catches nothing that happens while React renders it, so writing
 * it that way would look like error handling while handling nothing.
 */
async function load(): Promise<LoadResult> {
  try {
    // Every page, not the first one. The API orders projects by creation date,
    // and this list is sorted by risk -- so fetching a single page would sort
    // an arbitrary subset and could hide the highest-risk project entirely.
    // For a view whose whole purpose is "show me the worst thing", that is not
    // a cosmetic limit.
    const { items: data, truncated } = await collect<Project>(
      async (limit, offset) => {
        const page = await listProjects({ limit, offset });
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
      })),
    );
    return { ok: true, rows, truncated };
  } catch (error) {
    if (error instanceof MissingCredentialError) {
      return { ok: false, reason: "unconfigured", unauthorized: false };
    }
    return {
      ok: false,
      reason: "unreachable",
      unauthorized: error instanceof ApiError && error.isUnauthorized,
    };
  }
}

export default async function ProjectsPage() {
  const result = await load();

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
              title="The API is unreachable"
              description={
                result.unauthorized
                  ? "The dashboard's credential was rejected. Check SECUREOPS_API_TOKEN on the web service."
                  : "Nothing can be read right now. This is not the same as having no findings."
              }
            />
          </Card>
        </PageBody>
      </>
    );
  }

  const { rows, truncated } = result;

  const scored = rows.filter((r) => r.risk !== null).length;

  return (
    <>
      <PageHeader
        title="Projects"
        actions={
          <span className="text-[12px] tabular-nums text-ink-faint">
            {rows.length} {rows.length === 1 ? "project" : "projects"}
            {scored < rows.length && ` · ${rows.length - scored} never scanned`}
          </span>
        }
      />

      <PageBody>
        {rows.length === 0 ? (
          <Card>
            <EmptyState
              icon={<FolderOpenIcon className="size-4" />}
              title="No projects yet"
              description="Create one through the API, then submit a scan against it. Projects appear here as soon as they exist — a project with no scans is still a project."
            />
          </Card>
        ) : (
          <Card className="overflow-hidden">
            <div className="grid grid-cols-[minmax(0,1fr)_repeat(3,auto)] items-center gap-x-6 border-b border-line px-4 py-2">
              <span className="eyebrow">Project</span>
              <span className="eyebrow text-right">Risk</span>
              <span className="eyebrow text-right">Findings</span>
              <span className="eyebrow text-right">Last scan</span>
            </div>

            {rows
              // Worst first. A project list read top-down should put the thing
              // that needs attention at the top; alphabetical ordering would
              // hide it behind a name.
              .sort((a, b) => (b.risk?.score ?? -1) - (a.risk?.score ?? -1))
              .map(({ project, risk }) => (
                <Link
                  key={project.id}
                  href={`/projects/${project.id}`}
                  className={cn(
                    "grid grid-cols-[minmax(0,1fr)_repeat(3,auto)] items-center gap-x-6 border-b border-line px-4 py-3 last:border-b-0",
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

                  <div className="text-right">
                    {risk ? (
                      <div className="flex items-center justify-end gap-1.5">
                        <span
                          className={cn(
                            "text-[15px] font-medium tabular-nums",
                            scoreTone(risk.score),
                          )}
                        >
                          {risk.score.toFixed(1)}
                        </span>
                        {!risk.complete && (
                          <span
                            className="size-1.5 rounded-full bg-warn"
                            title="Computed from a scan with degraded coverage"
                          />
                        )}
                      </div>
                    ) : (
                      <span className="text-[13px] text-ink-faint">—</span>
                    )}
                  </div>

                  <div className="text-right text-[13px] tabular-nums text-ink-muted">
                    {risk ? risk.live_findings : <span className="text-ink-faint">—</span>}
                  </div>

                  <div className="text-right text-[12px] text-ink-faint">
                    {risk ? (
                      <RelativeTime value={risk.computed_at} />
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
