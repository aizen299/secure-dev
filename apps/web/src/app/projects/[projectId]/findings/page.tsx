import { ShieldCheckIcon } from "lucide-react";
import {
  listProjectFindings,
  collect,
  optional,
  MAX_PAGE,
  type Finding,
  type FindingStatus,
  type Severity,
} from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/security/empty";
import { FindingsBrowser } from "@/components/security/findings-browser";
import { FindingFilters } from "@/components/security/finding-filters";

export const dynamic = "force-dynamic";

/** Pages read before the list is declared partial. 100 per page. */
const MAX_PAGES = 10;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const STATUSES: FindingStatus[] = [
  "open",
  "acknowledged",
  "in_progress",
  "resolved",
  "reopened",
  "false_positive",
  "ignored",
];

/** Only values the API defines are forwarded; anything else is dropped rather
 *  than passed through to become a 400 (§15.8). */
function sanitise<T extends string>(value: string | undefined, allowed: T[]): T | undefined {
  return allowed.includes(value as T) ? (value as T) : undefined;
}

export default async function FindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { projectId } = await params;
  const search = await searchParams;

  const severity = sanitise(
    typeof search.severity === "string" ? search.severity : undefined,
    SEVERITIES,
  );
  const status = sanitise(
    typeof search.status === "string" ? search.status : undefined,
    STATUSES,
  );

  const result = await optional(() =>
    collect<Finding>(
      async (limit, offset) => {
        const page = await listProjectFindings(projectId, { limit, offset, severity, status });
        return { items: page.findings, hasMore: page.has_more };
      },
      MAX_PAGES,
    ),
  );

  const findings = result?.items ?? [];

  return (
    <PageBody className="space-y-4">
      <FindingFilters
        projectId={projectId}
        severity={severity}
        status={status}
        total={findings.length}
      />

      {findings.length === 0 ? (
        <Card>
          <EmptyState
            icon={<ShieldCheckIcon className="size-4" />}
            tone={severity || status ? "neutral" : "good"}
            title={
              severity || status
                ? "No findings match this filter"
                : "No findings in this project"
            }
            description={
              severity || status
                ? "Clear the filter to see everything this project has."
                : "Either nothing has been found, or nothing has been scanned yet — the scans tab says which."
            }
          />
        </Card>
      ) : (
        <>
          <FindingsBrowser findings={findings} />
          {result?.truncated && (
            <p className="text-[11px] text-ink-faint">
              Showing the first {MAX_PAGES * MAX_PAGE} findings. Narrow the filter to see
              the rest.
            </p>
          )}
        </>
      )}
    </PageBody>
  );
}
