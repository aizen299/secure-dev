import { WrenchIcon } from "lucide-react";
import { getProjectRemediation, optional, type RemediationAction } from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/security/empty";
import { Metric } from "@/components/security/metric";
import { SeverityBadge } from "@/components/security/severity";

export const dynamic = "force-dynamic";

/** See the overview page: `component` is only a component for an upgrade. */
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

/**
 * Where a statement came from.
 *
 * §11 makes vendor and scanner data authoritative and forbids presenting
 * anything generated as verified, so the source is rendered rather than
 * implied. `ai_explanation` is styled differently from the rest on purpose:
 * the model must make it structurally distinguishable, and so must the UI.
 */
function SourceBadge({ source }: { source: string }) {
  if (source === "ai_explanation") {
    return <Badge variant="accent">AI explanation — not verified</Badge>;
  }
  return <Badge variant="outline">{source}</Badge>;
}

export default async function RemediationPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const plan = await optional(() => getProjectRemediation(projectId));

  if (!plan || plan.actions.length === 0) {
    return (
      <PageBody>
        <Card>
          <EmptyState
            icon={<WrenchIcon className="size-4" />}
            title="Nothing actionable"
            description="A remediation action needs a fix a vendor actually published. Findings without one still exist — there is simply nothing to upgrade to yet."
          />
        </Card>
      </PageBody>
    );
  }

  // Ranked by risk removed, so the first is the one that sheds the most.
  const best = plan.actions.reduce((lowest, action) =>
    action.score_after < lowest.score_after ? action : lowest,
  );

  return (
    <PageBody className="space-y-4">
      <Card>
        <CardContent className="grid grid-cols-2 gap-4 pt-4 sm:grid-cols-3">
          <Metric label="Current score" value={plan.score.toFixed(1)} />
          <Metric label="Addressable findings" value={plan.addressable_findings} />
          {/* The single best action, not a cumulative total.
              `score_after` is computed per action, independently -- it is the
              score with that action's findings removed and nothing else. The
              aggregation is max-dominant (ADR 019), so the effect of taking
              several actions is not the sum, the product, or the last value in
              the list. Showing a combined figure would mean inventing a number
              the engine never produced, which is exactly what this platform
              refuses to do elsewhere. */}
          <Metric
            label="Best single action"
            value={best.score_after.toFixed(1)}
            tone="good"
            hint={`Taking #1 alone, from ${plan.score.toFixed(1)}`}
          />
        </CardContent>
      </Card>

      <p className="text-[12px] leading-relaxed text-ink-faint">
        Ranked by the risk each action removes, not by how many findings it closes. An
        action covering one critical finding outranks one covering ten informational
        ones, because that is what actually reduces exposure.
      </p>

      <div className="space-y-3">
        {plan.actions.map((action, index) => (
          <Card key={action.key}>
            <CardContent className="pt-3.5">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 w-5 shrink-0 text-right font-mono text-[12px] text-ink-faint">
                  {index + 1}
                </span>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-mono text-[13px] text-ink">
                      {actionLabel(action)}
                    </span>
                    <Badge variant="outline" className="capitalize">
                      {action.kind.replace(/_/g, " ")}
                    </Badge>
                  </div>

                  {action.fixed_versions && action.fixed_versions.length > 0 && (
                    <p className="mt-1 text-[12px] text-ink-muted">
                      Fixed in{" "}
                      <span className="font-mono text-ink">
                        {action.fixed_versions.join(", ")}
                      </span>
                    </p>
                  )}

                  {action.statements && action.statements.length > 0 && (
                    <div className="mt-2 space-y-1.5">
                      {action.statements.map((statement, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <SourceBadge source={statement.source} />
                          <p className="min-w-0 flex-1 text-[12px] leading-relaxed text-ink-muted">
                            {statement.text}
                          </p>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="mt-3 space-y-px rule pt-2.5">
                    {action.members.map((member) => (
                      <div
                        key={member.fingerprint}
                        className="grid grid-cols-[100px_minmax(0,1fr)_auto] items-baseline gap-3 py-1"
                      >
                        <SeverityBadge severity={member.severity} />
                        <span className="truncate text-[12px] text-ink-muted">
                          {member.title}
                        </span>
                        <span className="font-mono text-[11px] tabular-nums text-ink-faint">
                          {member.risk.toFixed(1)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="shrink-0 text-right">
                  <span className="block text-[15px] font-medium tabular-nums text-pass">
                    −{action.risk_removed.toFixed(1)}
                  </span>
                  <span className="block text-[11px] text-ink-faint">risk removed</span>
                  <span className="mt-1 block text-[11px] tabular-nums text-ink-faint">
                    → {action.score_after.toFixed(1)}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </PageBody>
  );
}
