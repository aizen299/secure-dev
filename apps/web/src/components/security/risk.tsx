import { cn } from "@/lib/utils";
import type { RiskPoint } from "@/lib/api";

/**
 * The project risk score, 0 (secure) to 100 (critical).
 *
 * Presented as a number with a scale beneath it rather than as a gauge or a
 * ring. Two reasons. The score is meaningful to two decimal places and a ring
 * cannot show that. And the aggregation is max-dominant (ADR 019), so the
 * distance between 60 and 70 is not the distance between 10 and 20 -- a gauge
 * would imply a linear reading the formula does not support.
 *
 * The band thresholds are presentation only. They colour the number; they never
 * feed a decision. Decisions come from the policy gate, which is deterministic
 * and explains itself (§12).
 */
function band(score: number): { label: string; text: string; bar: string } {
  if (score >= 75) return { label: "Critical", text: "text-critical", bar: "bg-critical" };
  if (score >= 50) return { label: "High", text: "text-high", bar: "bg-high" };
  if (score >= 25) return { label: "Elevated", text: "text-medium", bar: "bg-medium" };
  if (score > 0) return { label: "Low", text: "text-low", bar: "bg-low" };
  return { label: "Clear", text: "text-pass", bar: "bg-pass" };
}

export function RiskScore({
  score,
  complete,
  className,
}: {
  score: number;
  complete: boolean;
  className?: string;
}) {
  const { label, text, bar } = band(score);
  return (
    <div className={cn("space-y-2.5", className)}>
      <div className="flex items-baseline gap-2">
        <span className={cn("text-[44px] font-medium leading-none tabular-nums tracking-tight", text)}>
          {score.toFixed(1)}
        </span>
        <span className="text-[13px] text-ink-faint">/ 100</span>
        <span className={cn("ml-1 text-[12px] font-medium", text)}>{label}</span>
      </div>

      <div className="relative h-1 w-full overflow-hidden rounded-full bg-raised">
        <div
          className={cn("h-full rounded-full transition-[width] duration-500", bar)}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        />
      </div>

      {/* Coverage is stated next to the score rather than somewhere else on the
          page. A score computed from a degraded scan is a different claim from
          one computed from a complete scan, and putting the caveat anywhere but
          here invites reading the number without it (§12). */}
      {!complete && (
        <p className="text-[12px] leading-snug text-warn">
          Computed from a scan with degraded coverage — the real score can only be higher.
        </p>
      )}
    </div>
  );
}

/**
 * Risk over recent scans, as a sparkline.
 *
 * Hand-drawn SVG rather than a charting library: it is a polyline over at most
 * a few dozen points, and a chart library here would mean an axis system, a
 * tooltip layer, and a responsive container for something that needs none of
 * them. Recharts earns its place on the larger trend view, not here.
 *
 * Points are ordered oldest to newest, so the line reads left to right the way
 * a reader expects time to.
 */
export function RiskSparkline({
  history,
  className,
}: {
  history: RiskPoint[];
  className?: string;
}) {
  const points = [...history].reverse();
  if (points.length < 2) {
    return (
      <div className={cn("flex h-10 items-center text-[12px] text-ink-faint", className)}>
        Not enough history to plot a trend
      </div>
    );
  }

  const width = 240;
  const height = 40;
  const scores = points.map((p) => p.score);
  // A fixed 0-100 domain, not a fitted one. Auto-fitting would make a project
  // that moved from 2.0 to 2.4 look like a crisis.
  const path = scores
    .map((score, i) => {
      const x = (i / (scores.length - 1)) * width;
      const y = height - (Math.min(100, Math.max(0, score)) / 100) * height;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  // Indexed access is checked rather than asserted: the length guard above
  // already rules this out, and a non-null assertion here would be the kind of
  // "I know better" that survives a later edit to the guard.
  const latest = scores.at(-1) ?? 0;
  const previous = scores.at(-2) ?? latest;
  const delta = latest - previous;

  // Closing the path to the baseline gives the line a body, which is what
  // stops a fixed 0-100 domain from reading as a mostly-empty box.
  const area = `${path} L${width},${height} L0,${height} Z`;
  const tone = delta > 0 ? "text-critical" : delta < 0 ? "text-pass" : "text-ink-faint";

  return (
    <div className={cn("space-y-1.5", className)}>
      <div className="flex items-center gap-2">
        <span className="w-6 shrink-0 text-right font-mono text-[10px] text-ink-faint">100</span>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-10 flex-1"
          preserveAspectRatio="none"
          role="img"
          aria-label={`Risk score across the last ${points.length} scans, on a fixed 0 to 100 scale`}
        >
          <path d={area} fill="currentColor" className={cn(tone, "opacity-[0.13]")} />
          <path
            d={path}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
            className={tone}
          />
        </svg>
      </div>
      <p className="pl-8 text-[12px] text-ink-faint">
        {delta === 0 ? (
          "Unchanged since the previous scan"
        ) : (
          <>
            <span className={delta > 0 ? "text-critical" : "text-pass"}>
              {delta > 0 ? "+" : ""}
              {delta.toFixed(1)}
            </span>{" "}
            since the previous scan
          </>
        )}
      </p>
    </div>
  );
}
