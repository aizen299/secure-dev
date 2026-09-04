import Link from "next/link";
import { ArrowRightIcon, PlugZapIcon } from "lucide-react";
import {
  listProjects,
  getProjectRisk,
  collect,
  optional,
  MissingCredentialError,
  type Project,
  type Risk,
} from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { SetupNotice } from "@/components/shell/setup-notice";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/security/empty";
import { Metric } from "@/components/security/metric";
import { Pipeline, DotGrid } from "@/components/security/pipeline";
import { Reveal, Stagger, StaggerItem, Counter } from "@/components/security/motion";
import { ScanBar } from "@/components/security/scan-bar";
import { Logo } from "@/components/security/wordmark";
import { RelativeTime } from "@/components/security/relative-time";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

interface Row {
  project: Project;
  risk: Risk | null;
}

function scoreTone(score: number) {
  if (score >= 75) return "text-critical";
  if (score >= 50) return "text-high";
  if (score >= 25) return "text-medium";
  if (score > 0) return "text-low";
  return "text-pass";
}

type LoadResult = { ok: true; rows: Row[] } | { ok: false; reason: "unconfigured" | "unreachable" };

async function load(): Promise<LoadResult> {
  try {
    const { items } = await collect<Project>(async (limit, offset) => {
      const page = await listProjects({ limit, offset });
      return { items: page.data, hasMore: page.pagination.has_more };
    }, 20);

    const rows = await Promise.all(
      items.map(async (project) => ({
        project,
        risk: await optional(() => getProjectRisk(project.id)),
      })),
    );
    return { ok: true, rows };
  } catch (error) {
    if (error instanceof MissingCredentialError) return { ok: false, reason: "unconfigured" };
    return { ok: false, reason: "unreachable" };
  }
}

export default async function Home() {
  const result = await load();

  return (
    <PageBody className="space-y-7 py-10">
      <section className="relative space-y-4">
        <DotGrid />
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg bg-ink text-base">
            <Logo className="size-5" />
          </span>
          <div className="min-w-0">
            <h1 className="text-[20px] font-semibold tracking-tight text-ink">SecureOps</h1>
            <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-ink-muted">
              Turns fragmented security scanner output into one contextual security
              decision. Six scanners across secrets, dependencies, code, containers,
              infrastructure and running applications — reduced to one finding model,
              correlated, scored, and gated.
            </p>
          </div>
        </div>

        <Reveal delay={0.08}>
          <Pipeline />
        </Reveal>
      </section>

      <Reveal delay={0.14}>
        <section className="space-y-2.5">
          <h2 className="eyebrow">Scan a repository</h2>
          <ScanBar />
        </section>
      </Reveal>

      {!result.ok ? (
        result.reason === "unconfigured" ? (
          <SetupNotice />
        ) : (
          <Card>
            <EmptyState
              icon={<PlugZapIcon className="size-4" />}
              tone="warn"
              title="The API is unreachable"
              description="Nothing can be read right now. This is not the same as having no findings."
            />
          </Card>
        )
      ) : (
        <Fleet rows={result.rows} />
      )}
    </PageBody>
  );
}

function Fleet({ rows }: { rows: Row[] }) {
  const scored = rows.filter((r) => r.risk !== null);
  const findings = scored.reduce((sum, r) => sum + (r.risk?.live_findings ?? 0), 0);
  const worst = [...scored].sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0)).slice(0, 5);
  const degraded = scored.filter((r) => r.risk && !r.risk.complete).length;

  return (
    <section className="space-y-4">
      <Stagger className="grid grid-cols-2 gap-6 sm:grid-cols-4">
        <StaggerItem>
          <Metric label="Projects" value={<Counter value={rows.length} />} />
        </StaggerItem>
        <StaggerItem>
          <Metric
            label="Scored"
            value={<Counter value={scored.length} />}
            hint={`${rows.length - scored.length} never scanned`}
          />
        </StaggerItem>
        <StaggerItem>
          <Metric label="Live findings" value={<Counter value={findings} />} />
        </StaggerItem>
        <StaggerItem>
          <Metric
            label="Degraded coverage"
            value={<Counter value={degraded} />}
            tone={degraded > 0 ? "warn" : "faint"}
            hint={degraded > 0 ? "Scored from incomplete scans" : "All scores from complete scans"}
          />
        </StaggerItem>
      </Stagger>

      {worst.length > 0 && (
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <span className="eyebrow">Highest risk</span>
            <Link
              href="/projects"
              className="inline-flex items-center gap-1 text-[12px] text-ink-faint hover:text-ink-muted"
            >
              All projects <ArrowRightIcon className="size-3" />
            </Link>
          </div>
          {worst.map(({ project, risk }, i) => (
            <Reveal key={project.id} delay={0.04 * i}>
            <Link
              href={`/projects/${project.id}`}
              className="group flex items-center gap-4 border-b border-line px-4 py-2.5 last:border-b-0 transition-colors duration-100 hover:bg-raised/60"
            >
              <span className={cn("w-14 shrink-0 text-[15px] font-medium tabular-nums", scoreTone(risk!.score))}>
                {risk!.score.toFixed(1)}
              </span>
              <span className="min-w-0 flex-1 truncate text-[13px] text-ink">{project.name}</span>
              <span className="shrink-0 text-[12px] tabular-nums text-ink-faint">
                {risk!.live_findings} findings
              </span>
              <span className="hidden shrink-0 text-[12px] text-ink-faint sm:block">
                <RelativeTime value={risk!.computed_at} />
              </span>
              <ArrowRightIcon className="size-3 shrink-0 text-ink-faint opacity-0 transition-opacity duration-100 group-hover:opacity-100" />
            </Link>
            </Reveal>
          ))}
        </Card>
      )}
    </section>
  );
}
