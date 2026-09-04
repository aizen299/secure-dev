import { NextResponse } from "next/server";
import { hasSession } from "@/lib/guard";
import { getScan, ApiError } from "@/lib/api";

/**
 * Scan progress, for the browser to poll while a scan runs.
 *
 * Returns the real state -- which scanners have reported and how each fared --
 * rather than a percentage invented to fill a progress bar. A scan takes
 * thirty to seventy-five seconds, so there is genuine progress to show, and
 * showing the real thing is both more interesting and more honest than a
 * spinner over a fixed delay.
 */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ scanId: string }> },
) {
  if (!(await hasSession())) {
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }
  const { scanId } = await params;

  try {
    const scan = await getScan(scanId);
    return NextResponse.json({
      status: scan.status,
      complete_coverage: scan.complete_coverage,
      results: (scan.results ?? []).map((r) => ({
        scanner: r.scanner,
        status: r.status,
        duration_ms: r.duration_ms,
        degraded: (r.degradations ?? []).length > 0,
      })),
      requested: scan.requested_scanners ?? [],
    });
  } catch (error) {
    if (error instanceof ApiError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "unreachable" }, { status: 502 });
  }
}
