import { NextResponse } from "next/server";
import { listProjects, ApiError, MissingCredentialError } from "@/lib/api";

/**
 * Data for the command palette.
 *
 * A route handler rather than a client fetch to the SecureOps API directly:
 * the credential lives in this process's environment and must not reach the
 * browser (§15.4). What crosses the wire is the projects the palette needs to
 * offer as destinations, and nothing else.
 *
 * Note what this does NOT add: authorization. Anyone who can reach the
 * dashboard can reach this route, which is exactly the exposure the pages
 * themselves already have. Per-user identity is Phase 11 (T-23), and adding a
 * half-measure here would suggest a protection that is not there.
 */
export async function GET() {
  try {
    const { data } = await listProjects({ limit: 100 });
    return NextResponse.json({
      projects: data.map((p) => ({
        id: p.id,
        name: p.name,
        slug: p.slug,
        environment: p.environment,
        criticality: p.criticality,
      })),
    });
  } catch (error) {
    if (error instanceof MissingCredentialError) {
      return NextResponse.json({ projects: [], reason: "unconfigured" }, { status: 200 });
    }
    if (error instanceof ApiError) {
      // The upstream message is not forwarded: it can carry internal detail,
      // and the palette only needs to know it has nothing to offer (§15.3).
      return NextResponse.json({ projects: [], reason: "unavailable" }, { status: 200 });
    }
    return NextResponse.json({ projects: [], reason: "unavailable" }, { status: 200 });
  }
}
