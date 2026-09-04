import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import { setProjectArchived, ApiError } from "@/lib/api";

/**
 * Archives a project, or brings it back.
 *
 * Archive, never delete: §17 requires security-relevant records to be soft
 * deleted, and a project's scans, findings and audit trail are exactly that.
 * The API refuses this to anyone but an administrator, and to an administrator
 * whose scope does not include the project.
 */
export async function POST(request: Request, context: { params: Promise<{ projectId: string }> }) {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const { projectId } = await context.params;
  const body = (await request.json().catch(() => null)) as { archived?: boolean } | null;
  if (typeof body?.archived !== "boolean") {
    return NextResponse.json({ error: "archived must be true or false" }, { status: 400 });
  }

  try {
    return NextResponse.json(await setProjectArchived(projectId, body.archived));
  } catch (error) {
    if (error instanceof ApiError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "The API is unreachable." }, { status: 502 });
  }
}
