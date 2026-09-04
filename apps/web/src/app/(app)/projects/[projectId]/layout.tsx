import Link from "next/link";
import { notFound } from "next/navigation";
import {
  getProject,
  whoAmI,
  tolerant,
  ApiError,
  MissingCredentialError,
  type Project,
} from "@/lib/api";
import { PageHeader, PageBody } from "@/components/shell/page-header";
import { SetupNotice } from "@/components/shell/setup-notice";
import { Badge } from "@/components/ui/badge";
import { ProjectTabs } from "@/components/shell/project-tabs";
import { ArchiveToggle } from "@/components/security/archive-toggle";

export const dynamic = "force-dynamic";

type LoadResult =
  | { ok: true; project: Project }
  | { ok: false; reason: "unconfigured" };

/**
 * Loads the project, resolving the two outcomes this layout renders
 * differently.
 *
 * The await is inside the try and the JSX is not, deliberately: a try/catch
 * around returned JSX does not catch anything that happens while React renders
 * it, so writing it that way would look like error handling while handling
 * nothing. A missing project is a 404 and a missing credential is a
 * configuration screen; everything else propagates to the error boundary,
 * which is the thing that actually catches render failures.
 */
async function load(projectId: string): Promise<LoadResult> {
  try {
    return { ok: true, project: await getProject(projectId) };
  } catch (error) {
    if (error instanceof MissingCredentialError) return { ok: false, reason: "unconfigured" };
    if (error instanceof ApiError && error.isNotFound) notFound();
    throw error;
  }
}

export default async function ProjectLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  // Together: independent reads, and the identity only decides whether to offer
  // a control the API gates anyway.
  const [result, me] = await Promise.all([load(projectId), tolerant(() => whoAmI())]);

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Project" />
        <PageBody>
          <SetupNotice />
        </PageBody>
      </>
    );
  }

  const { project } = result;

  return (
    <>
      <PageHeader
        eyebrow={
          <Link href="/projects" className="hover:text-ink-muted">
            Projects
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            {project.name}
            {project.environment === "production" && <Badge variant="outline">prod</Badge>}
            {project.internet_facing && <Badge variant="outline">internet-facing</Badge>}
            <Badge variant="outline">{project.criticality} criticality</Badge>
            {/* Said plainly on the project's own page. An archived project is
                still reachable by URL and still scannable -- what changed is
                that it stopped appearing in lists, and a person who followed a
                bookmark here deserves to know which it is. */}
            {project.archived && <Badge variant="outline">archived</Badge>}
          </span>
        }
        actions={
          me?.role === "admin" ? (
            <ArchiveToggle projectId={projectId} archived={project.archived} />
          ) : undefined
        }
      >
        <ProjectTabs projectId={projectId} />
      </PageHeader>
      {children}
    </>
  );
}
