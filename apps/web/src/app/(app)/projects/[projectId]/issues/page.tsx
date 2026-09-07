import { LinkIcon } from "lucide-react";
import { listProjectIssues, optional } from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { EmptyState } from "@/components/security/empty";
import { SeverityBadge } from "@/components/security/severity";

export const dynamic = "force-dynamic";

const KEY_LABEL: Record<string, string> = {
  cve: "Same vulnerability",
  purl: "Same component",
  file: "Same file",
};

export default async function IssuesPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const issues = await optional(() => listProjectIssues(projectId, { limit: 50 }));

  if (!issues || issues.issues.length === 0) {
    return (
      <PageBody>
        <Card>
          <EmptyState
            icon={<LinkIcon className="size-4" />}
            title="No correlated issues"
            description="An issue forms when two or more findings share a vulnerability, a component, or a file. A project can have many findings and no issues — that means nothing was found twice."
          />
        </Card>
      </PageBody>
    );
  }

  return (
    <PageBody className="space-y-3">
      <p className="text-[12px] leading-relaxed text-ink-faint">
        Findings that share an attribute are one problem seen more than once. An issue
        spanning two security domains is rated one step above its worst member — a
        vulnerable dependency that code also misuses is worse than either fact alone.
      </p>

      {issues.issues.map((issue) => (
        <Card key={issue.id}>
          <CardContent className="pt-3.5">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={issue.severity} />
              {issue.escalated && (
                // The escalation is shown as a claim, not folded silently into
                // the value (ADR 017).
                <Badge variant="accent">escalated</Badge>
              )}
              <Badge variant="outline">{KEY_LABEL[issue.key_kind] ?? issue.key_kind}</Badge>
              <span className="truncate font-mono text-[12px] text-ink-muted">
                {issue.key_value}
              </span>
            </div>

            <p className="mb-3 text-[13px] leading-relaxed text-ink-muted">
              {issue.explanation}
            </p>

            {/* Deployment evidence, shown because the argument for not acting
                on it automatically depends on a person seeing it: they can
                dismiss a finding with a reason recorded, which is better than a
                number that moved for reasons nobody reviewed (ADR 037).

                Rendered as a note rather than a badge beside the severity. A
                badge next to `escalated` would read as a modifier of the
                severity, and this deliberately is not one. */}
            {issue.deployment_evidence && (
              <p
                className={cn(
                  "mb-3 rounded-md border px-3 py-2 text-[12px] leading-relaxed",
                  issue.deployment === "not_deployed"
                    ? "border-line-strong bg-raised/40 text-ink-muted"
                    : "border-warn/25 bg-warn-dim text-warn",
                )}
              >
                {issue.deployment_evidence}
              </p>
            )}

            <div className="space-y-px rule pt-3">
              {issue.members.map((member) => (
                <div
                  key={member.fingerprint}
                  className="grid grid-cols-[100px_minmax(0,1fr)_auto] items-baseline gap-3 py-1.5"
                >
                  <SeverityBadge severity={member.severity} />
                  <div className="min-w-0">
                    <p className="truncate text-[13px] text-ink">{member.title}</p>
                    {/* Every membership carries the evidence for it. SecureOps
                        does not assert a relationship it cannot explain (§9). */}
                    <p className="truncate text-[12px] text-ink-faint">{member.evidence}</p>
                  </div>
                  <span className="font-mono text-[11px] text-ink-faint">{member.scanner}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </PageBody>
  );
}
