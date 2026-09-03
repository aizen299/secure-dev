import Link from "next/link";
import { ShieldCheckIcon, ScanLineIcon, ArrowRightIcon, TriangleAlertIcon } from "lucide-react";
import {
  getProjectRisk,
  getProjectRemediation,
  listProjectFindings,
  listProjectScans,
  getScanGate,
  optional,
  collect,
  MAX_PAGE,
  type Severity,
  type Finding,
  type RemediationAction,
} from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/security/empty";
import { Metric } from "@/components/security/metric";
import { RiskScore, RiskSparkline } from "@/components/security/risk";
import { SeverityBar, SeverityLegend } from "@/components/security/severity";
import { VerdictBadge } from "@/components/security/verdict";
import { ScanStatusBadge } from "@/components/security/status";
import { RelativeTime } from "@/components/security/relative-time";

export const dynamic = "force-dynamic";

/**
 * How many pages of findings the distribution reads.
 *
 * The API caps a page at 100, so this is 1,000 findings. Past that the bar is
 * labelled as partial rather than quietly describing a fraction of the project
 * as if it were the whole.
 */
const DISTRIBUTION_PAGES = 10;

export default async function ProjectOverview({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;

  // Loaded together: these are independent reads and serialising them would
  // make the page as slow as their sum for no reason.
  const [risk, remediation, findings, scans] = await Promise.all([
    optional(() => getProjectRisk(projectId)),
    optional(() => getProjectRemediation(projectId)),
    optional(() =>
      collect<Finding>(
        async (limit, offset) => {
          const page = await listProjectFindings(projectId, { limit, offset, status: "open" });
          return { items: page.findings, hasMore: page.has_more };
        },
        DISTRIBUTION_PAGES,
      ),
    ),
    optional(() => listProjectScans(projectId, { limit: 5 })),
  ]);

  const latestScan = scans?.data?.[0];
  const gate = latestScan ? await optional(() => getScanGate(latestScan.id)) : null;

  if (!risk && !latestScan) {
    return (
      <PageBody>
        <Card>
          <EmptyState
            icon={<ScanLineIcon className="size-4" />}
            title="This project has never been scanned"
            description="Submit a scan through POST /api/v1/scans. Findings, risk, and the gate verdict all follow from a scan — none of them exist before one has run."
          />
        </Card>
      </PageBody>
    );
  }

  const counts = (findings?.items ?? []).reduce<Partial<Record<Severity, number>>>(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] ?? 0) + 1 }),
    {},
  );
  const sampled = findings?.items.length ?? 0;
  const truncated = findings?.truncated ?? false;

  return (
    <PageBody className="space-y-4">
      {/* Coverage first, above everything. A degraded scan changes how every
          number below it should be read, so it cannot sit further down the
          page than the numbers it qualifies (§12). */}
      {risk && !risk.complete && (
        <div className="flex items-start gap-2.5 rounded-lg border border-warn/25 bg-warn-dim px-3.5 py-3">
          <TriangleAlertIcon className="mt-px size-3.5 shrink-0 text-warn" />
          <div className="space-y-0.5">
            <p className="text-[13px] font-medium text-warn">Coverage is incomplete</p>
            <p className="text-[12px] leading-relaxed text-ink-muted">
              The most recent scan finished as{" "}
              <span className="font-mono">{risk.scan_status}</span>. Everything below is
              computed from what was actually scanned — the true figures can only be worse,
              never better.
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Risk</CardTitle>
            {risk && (
              <span className="font-mono text-[11px] text-ink-faint" title="Weights digest">
                {risk.weights_digest.slice(0, 8)}
              </span>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {risk ? (
              <>
                <RiskScore score={risk.score} complete={risk.complete} />
                <div className="rule pt-3">
                  <RiskSparkline history={risk.history ?? []} />
                </div>
                <div className="grid grid-cols-2 gap-4 rule pt-3">
                  <Metric label="Live findings" value={risk.live_findings} />
                  <Metric
                    label="Dismissed"
                    value={risk.dismissed_findings}
                    tone="faint"
                    hint={risk.dismissed_findings > 0 ? "Excluded from the score" : undefined}
                  />
                </div>
              </>
            ) : (
              <EmptyState
                title="No score yet"
                description="A risk score is computed when a scan completes."
              />
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Gate</CardTitle>
              {gate && <VerdictBadge verdict={gate.verdict} size="lg" />}
            </CardHeader>
            <CardContent>
              {gate ? (
                <div className="space-y-3">
                  <p className="text-[13px] leading-relaxed text-ink-muted">{gate.summary}</p>

                  {gate.coverage.downgraded && (
                    <p className="text-[12px] leading-relaxed text-warn">
                      The verdict was downgraded because the scan did not complete. A gate
                      that passes a broken scan is worse than one that fails a real finding.
                    </p>
                  )}

                  <div className="space-y-1 rule pt-3">
                    {gate.conditions.map((condition, i) => (
                      <div
                        key={`${condition.kind}-${condition.selector ?? ""}-${i}`}
                        className="flex items-baseline justify-between gap-4 py-1"
                      >
                        <span className="min-w-0 flex-1 truncate text-[12px] text-ink-muted">
                          {condition.explanation}
                        </span>
                        <span
                          className={`shrink-0 font-mono text-[12px] tabular-nums ${
                            condition.breached ? "text-fail" : "text-ink-faint"
                          }`}
                        >
                          {condition.observed} / {condition.max}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No gate result"
                  description="The gate is evaluated when a scan completes."
                />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Open findings by severity</CardTitle>
              <Button variant="ghost" size="sm" asChild>
                <Link href={`/projects/${projectId}/findings`}>
                  All findings <ArrowRightIcon />
                </Link>
              </Button>
            </CardHeader>
            <CardContent className="space-y-3">
              {sampled === 0 ? (
                <EmptyState
                  icon={<ShieldCheckIcon className="size-4" />}
                  tone="good"
                  title="No open findings"
                  description="Every finding this project has is resolved or dismissed."
                />
              ) : (
                <>
                  <SeverityBar counts={counts} />
                  <SeverityLegend counts={counts} />
                  {truncated && (
                    <p className="text-[11px] text-ink-faint">
                      Counted across the first {DISTRIBUTION_PAGES * MAX_PAGE} open findings;
                      this project has more.
                    </p>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Where to start</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link href={`/projects/${projectId}/remediation`}>
                Full plan <ArrowRightIcon />
              </Link>
            </Button>
          </CardHeader>
          <CardContent>
            {remediation && remediation.actions.length > 0 ? (
              <ol className="space-y-2.5">
                {remediation.actions.slice(0, 4).map((action, i) => (
                  <li key={action.key} className="flex items-start gap-3">
                    <span className="mt-0.5 w-4 shrink-0 text-right font-mono text-[11px] text-ink-faint">
                      {i + 1}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] text-ink">
                        {actionLabel(action)}
                      </p>
                      <p className="mt-0.5 text-[12px] text-ink-faint">
                        <span className="capitalize text-ink-muted">
                          {actionKindLabel(action.kind)}
                        </span>{" "}
                        · {action.members.length}{" "}
                        {action.members.length === 1 ? "finding" : "findings"}
                        {action.fixed_versions && action.fixed_versions.length > 0 && (
                          <> · to {action.fixed_versions.join(", ")}</>
                        )}
                      </p>
                    </div>
                    {/* Ranked by risk removed, not by count or severity. That
                        is the whole point of ADR 020, so it is the number the
                        row leads with. */}
                    <span className="shrink-0 text-right">
                      <span className="block text-[13px] font-medium tabular-nums text-pass">
                        −{action.risk_removed.toFixed(1)}
                      </span>
                      <span className="block text-[11px] text-ink-faint">risk</span>
                    </span>
                  </li>
                ))}
              </ol>
            ) : (
              <EmptyState
                title="Nothing actionable yet"
                description="A remediation action needs a vendor-supplied fix. Findings without one are still listed, but there is nothing to upgrade to."
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent scans</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link href={`/projects/${projectId}/scans`}>
                All scans <ArrowRightIcon />
              </Link>
            </Button>
          </CardHeader>
          <CardContent>
            {scans && scans.data.length > 0 ? (
              <ul className="space-y-2">
                {scans.data.map((scan) => (
                  <li key={scan.id}>
                    <Link
                      href={`/projects/${projectId}/scans/${scan.id}`}
                      className="flex items-center gap-3 rounded-md px-1.5 py-1.5 transition-colors duration-75 hover:bg-raised/60"
                    >
                      <ScanStatusBadge status={scan.status} />
                      <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink-muted">
                        {scan.target.repository_url ??
                          scan.target.image ??
                          scan.target.endpoint_url ??
                          scan.target.kind}
                      </span>
                      <span className="shrink-0 text-[12px] text-ink-faint">
                        <RelativeTime value={scan.queued_at} />
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No scans" description="Nothing has been submitted yet." />
            )}
          </CardContent>
        </Card>
      </div>
    </PageBody>
  );
}

/**
 * What to call a remediation action.
 *
 * `component` is only a component for an upgrade. For the other kinds the API
 * puts the finding's fingerprint there -- 64 hex characters that tell a reader
 * nothing and take the whole width of the row to say it -- so those are named
 * by the finding they cover instead.
 *
 * This branches on the action's kind, which is a domain concept, and never on
 * which scanner produced it (§7 rule 2, §25.3).
 */
function actionLabel(action: RemediationAction): string {
  if (action.kind === "upgrade" && action.component) return action.component;

  const first = action.members[0];
  if (first) {
    return action.members.length > 1
      ? `${first.title} +${action.members.length - 1} more`
      : first.title;
  }
  return action.kind.replace(/_/g, " ");
}

/** A human label for the action kind, shown beside what it applies to. */
function actionKindLabel(kind: string): string {
  return kind.replace(/_/g, " ");
}
