import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import { updateUser, ApiError } from "@/lib/api";

/**
 * Changes a role, an enabled state, or membership.
 *
 * Only the fields present are forwarded, so an omitted one is left alone by the
 * API as well as by the caller. Sending `undefined` through would serialise
 * away, but building the object explicitly makes the intent readable rather
 * than incidental.
 */
export async function PATCH(request: Request, context: { params: Promise<{ userId: string }> }) {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const { userId } = await context.params;
  const body = (await request.json().catch(() => null)) as {
    role?: "viewer" | "engineer" | "admin";
    disabled?: boolean;
    projects?: string[];
  } | null;

  const changes: { role?: "viewer" | "engineer" | "admin"; disabled?: boolean; projects?: string[] } = {};
  if (body?.role !== undefined) changes.role = body.role;
  if (body?.disabled !== undefined) changes.disabled = body.disabled;
  if (body?.projects !== undefined) changes.projects = body.projects;

  if (Object.keys(changes).length === 0) {
    return NextResponse.json({ error: "Nothing to change." }, { status: 400 });
  }

  try {
    return NextResponse.json(await updateUser(userId, changes));
  } catch (error) {
    if (error instanceof ApiError) {
      // 409 here is the last-administrator guard, and its message says what to
      // do about it. Forwarded rather than replaced.
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "The API is unreachable." }, { status: 502 });
  }
}
