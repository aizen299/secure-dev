import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import {
  createProject,
  createScan,
  listProjects,
  validateTarget,
  collect,
  ApiError,
  type Project,
} from "@/lib/api";

/**
 * Submits a scan from the dashboard.
 *
 * Gated on the session (ADR 029). Before the login existed this endpoint could
 * not have existed: an anonymous page able to queue clones is a way to make the
 * worker fetch arbitrary URLs.
 *
 * The repository URL is not validated for safety here beyond an obvious shape
 * check. That is deliberate -- the API applies the real address policy and the
 * argument-injection defences, and a second, weaker implementation of those
 * rules in the browser tier would be a place for the two to disagree.
 */
export async function POST(request: Request) {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const body = (await request.json().catch(() => null)) as {
    repository_url?: string;
    ref?: string;
    kind?: string;
  } | null;

  const url = (body?.repository_url ?? "").trim();
  const ref = (body?.ref ?? "").trim() || "main";
  // Repository or endpoint, chosen in the UI rather than guessed from the URL.
  // A heuristic -- ".git means repository", "github.com means repository" --
  // would silently clone a website or crawl a repository host, and the failure
  // would look like the platform being broken rather than the guess being
  // wrong.
  const kind = body?.kind === "endpoint" ? "endpoint" : "repository";

  if (!/^https:\/\/\S+$/.test(url)) {
    return NextResponse.json(
      { error: `Enter an https ${kind === "endpoint" ? "URL" : "repository URL"}.` },
      { status: 400 },
    );
  }

  // A slug derived from the URL, so pasting the same target twice reuses its
  // project rather than creating a second one that splits its history.
  //
  // The kind is part of it. A repository and a deployed site can share a path,
  // and folding them into one project would put findings about source code and
  // findings about a running application under one risk score without either
  // having been correlated to the other.
  const slug = kind === "endpoint" ? slugForEndpoint(url) : slugFor(url);
  if (!slug) {
    return NextResponse.json({ error: "Could not derive a project name from that URL." }, { status: 400 });
  }

  const target =
    kind === "endpoint"
      ? ({ kind: "endpoint", endpoint_url: url } as const)
      : ({ kind: "repository", repository_url: url, ref } as const);

  try {
    // Validated BEFORE a project is created (ADR 032).
    //
    // The order used to be the other way round, and a refused target left a
    // project named after it with no scans -- indistinguishable in the fleet
    // list from one somebody meant to create. Submitting the SSRF probe
    // `https://169.254.169.254/latest/meta-data/` produced exactly that: the
    // address policy did its job and the junk stayed.
    //
    // The check is not repeated here in the browser tier. This asks the API
    // what it thinks; a second, weaker copy of those rules would be a place for
    // the two to disagree, and the weaker one would decide what gets created.
    await validateTarget(target);

    const existing = await findProjectBySlug(slug);

    // An archived project is the one case where reusing it would be wrong.
    //
    // Archiving stops a project accepting new scans, so submitting one against
    // it would be refused by the API anyway -- and silently restoring it to get
    // past that would undo a decision somebody made deliberately. Creating a
    // second project for the same target is worse still: it splits the target's
    // history in two.
    //
    // So this is a refusal, and the whole value of it is the message. The
    // previous behaviour reported the unique-index collision verbatim -- "a
    // project with that slug already exists" -- which is true, useless, and
    // describes a project the person cannot see.
    if (!existing) {
      const archivedProject = await findProjectBySlug(slug, true);
      if (archivedProject) {
        return NextResponse.json(
          {
            error:
              `${archivedProject.name} is archived, so it accepts no new scans. ` +
              `Restore it from Projects → Archived to scan this target again.`,
            project_id: archivedProject.id,
          },
          { status: 409 },
        );
      }
    }

    let project = existing;
    if (!project) {
      try {
        project = await createProject({
          name: titleFor(slug),
          slug,
          environment: "development",
          criticality: "medium",
        });
      } catch (error) {
        // A slug collision here means the project exists and is OUT OF SCOPE:
        // the lookups above cover both the visible case and the archived one,
        // so the only way to reach a collision is a project this person cannot
        // see. Somebody else scanned the same target.
        //
        // The message deliberately does NOT name it. The archived branch above
        // does, and may: that project was found through a scoped lookup, so the
        // caller can already see it. This one cannot, and naming a project
        // outside somebody's scope would disclose more than the collision
        // already does (T-38).
        //
        // Membership is NOT granted here, though the parallel with "a creator
        // becomes a member" is tempting. That grant follows from creating a
        // project; this would follow from GUESSING one, and a slug derives from
        // a URL anybody can type -- so it would let any `service` credential
        // join any project, and read its findings, by naming the right target.
        if (error instanceof ApiError && error.status === 409) {
          return NextResponse.json(
            {
              error:
                "Another project already tracks this target, and your account " +
                "cannot reach it. Ask an administrator to add you to it.",
            },
            { status: 409 },
          );
        }
        throw error;
      }
    }

    const scan = await createScan(
      kind === "endpoint"
        ? { project_id: project.id, target }
        : { project_id: project.id, target, branch: ref },
    );

    return NextResponse.json({ project_id: project.id, scan_id: scan.id, slug });
  } catch (error) {
    if (error instanceof ApiError) {
      // The upstream message is forwarded here, unlike elsewhere: these are
      // validation errors about a URL the user just typed ("scheme must be
      // https", "blocked address"), and hiding them would leave someone
      // guessing at what the platform rejected.
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "The API is unreachable." }, { status: 502 });
  }
}

/**
 * Finds the project a slug names, across every page.
 *
 * One page was not enough, and the failure was silent: past 100 projects a
 * target's own project became invisible here, so the next scan of it tried to
 * create a second one and collided on the unique index -- reported as "a
 * project with that slug already exists", about a project the caller could not
 * see. Paging costs a request per hundred projects and removes a cliff nobody
 * would recognise when they hit it.
 */
async function findProjectBySlug(slug: string, archived = false) {
  const { items } = await collect<Project>(
    async (limit, offset) => {
      const page = await listProjects({ limit, offset, archived });
      return { items: page.data, hasMore: page.pagination.has_more };
    },
    MAX_PROJECT_PAGES,
  );
  return items.find((p) => p.slug === slug) ?? null;
}

/** Pages of projects read before the slug lookup gives up. 100 per page. */
const MAX_PROJECT_PAGES = 20;

/** `https://github.com/owner/repo.git` -> `owner-repo`. */
function slugFor(url: string): string {
  const path = url
    .replace(/^https:\/\/[^/]+\//, "")
    .replace(/\.git$/, "")
    .replace(/\/+$/, "");
  const slug = path
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug.slice(0, 60);
}

/** `https://example.com/app` -> `site-example-com-app`. */
function slugForEndpoint(url: string): string {
  const withoutScheme = url.replace(/^https:\/\//, "").replace(/\/+$/, "");
  const slug = withoutScheme
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug ? `site-${slug}`.slice(0, 60) : "";
}

function titleFor(slug: string): string {
  return slug
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
