import { getReadiness, type DependencyState, type ReadinessResponse } from "@/lib/api";

// The platform status reflects live backend state, so this page must never be
// prerendered at build time.
export const dynamic = "force-dynamic";

type LoadResult =
  | { ok: true; readiness: ReadinessResponse }
  | { ok: false; message: string };

async function loadReadiness(): Promise<LoadResult> {
  try {
    return { ok: true, readiness: await getReadiness() };
  } catch {
    // The reason is deliberately generic: a connection error can contain
    // internal host detail (CLAUDE.md §15.3).
    return { ok: false, message: "API is unreachable" };
  }
}

function statusColor(status: string): string {
  if (status === "ok") return "text-ok";
  if (status === "degraded") return "text-degraded";
  return "text-critical";
}

function DependencyRow({ dependency }: { dependency: DependencyState }) {
  return (
    <li className="flex items-center justify-between border-b border-border py-3 last:border-b-0">
      <span className="font-mono text-sm">{dependency.name}</span>
      <span className={`font-mono text-sm ${statusColor(dependency.status)}`}>
        {dependency.status}
      </span>
    </li>
  );
}

export default async function Home() {
  const result = await loadReadiness();

  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-8 px-6 py-16">
      <header className="flex flex-col gap-2">
        <h1 className="text-3xl font-semibold tracking-tight">SecureOps</h1>
        <p className="text-muted">
          Turns fragmented security scanner output into one contextual security decision.
        </p>
      </header>

      <section className="rounded-lg border border-border bg-panel p-6">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-muted">
          Platform status
        </h2>

        {result.ok ? (
          <>
            <p className={`mb-4 font-mono text-lg ${statusColor(result.readiness.status)}`}>
              {result.readiness.status}
            </p>
            <ul>
              {result.readiness.dependencies.map((dependency) => (
                <DependencyRow key={dependency.name} dependency={dependency} />
              ))}
            </ul>
          </>
        ) : (
          <p className="font-mono text-lg text-critical">{result.message}</p>
        )}
      </section>

      <section className="rounded-lg border border-border bg-panel p-6">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">
          Phase 1 &mdash; foundation
        </h2>
        <p className="text-sm leading-relaxed text-muted">
          Scanner orchestration, normalization, correlation, risk scoring, remediation, and
          security gates are not implemented yet. This shell verifies the API, PostgreSQL,
          and Redis wiring that later phases build on.
        </p>
      </section>
    </main>
  );
}
