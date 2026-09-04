import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import { createProject, createScan, listProjects, ApiError } from "@/lib/api";

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
  } | null;

  const url = (body?.repository_url ?? "").trim();
  const ref = (body?.ref ?? "").trim() || "main";

  if (!/^https:\/\/\S+$/.test(url)) {
    return NextResponse.json(
      { error: "Enter an https repository URL." },
      { status: 400 },
    );
  }

  // A slug derived from the URL, so pasting the same repository twice reuses
  // its project rather than creating a second one that splits its history.
  const slug = slugFor(url);
  if (!slug) {
    return NextResponse.json({ error: "Could not derive a project name from that URL." }, { status: 400 });
  }

  try {
    const existing = await findProjectBySlug(slug);
    const project = existing ?? (await createProject({
      name: titleFor(slug),
      slug,
      environment: "development",
      criticality: "medium",
    }));

    const scan = await createScan({
      project_id: project.id,
      target: { kind: "repository", repository_url: url, ref },
      branch: ref,
    });

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

async function findProjectBySlug(slug: string) {
  const { data } = await listProjects({ limit: 100 });
  return data.find((p) => p.slug === slug) ?? null;
}

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

function titleFor(slug: string): string {
  return slug
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
