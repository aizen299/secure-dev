import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/api";

/**
 * Severity presentation, defined once.
 *
 * Severity is the single most-read signal in the product, so its colour, its
 * order, and its wording live in one place. A second definition anywhere else
 * is how two screens come to disagree about what "high" looks like.
 *
 * `unknown` is a real value and is deliberately not styled as `info`: a scanner
 * declining to assess something is a different fact from assessing it as
 * harmless, and ADR 018 keeps that distinction everywhere else too.
 */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "unknown",
];

const SEVERITY_STYLE: Record<Severity, { chip: string; dot: string; text: string }> = {
  critical: { chip: "border-critical/25 bg-critical-dim text-critical", dot: "bg-critical", text: "text-critical" },
  high: { chip: "border-high/25 bg-high-dim text-high", dot: "bg-high", text: "text-high" },
  medium: { chip: "border-medium/25 bg-medium-dim text-medium", dot: "bg-medium", text: "text-medium" },
  low: { chip: "border-low/25 bg-low-dim text-low", dot: "bg-low", text: "text-low" },
  info: { chip: "border-line-strong bg-info-dim text-info", dot: "bg-info", text: "text-info" },
  unknown: { chip: "border-line-strong bg-unknown-dim text-unknown", dot: "bg-unknown", text: "text-unknown" },
};

export function severityStyle(severity: Severity) {
  return SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.unknown;
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  const style = severityStyle(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5",
        "text-[11px] font-medium leading-none capitalize",
        style.chip,
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full", style.dot)} aria-hidden />
      {severity}
    </span>
  );
}

/**
 * The severity distribution as a single proportional bar.
 *
 * A stacked bar rather than a pie or a donut: the question an operator asks is
 * "how much of this is critical", which is a length comparison. Pies make that
 * comparison harder for no gain, and a donut with a number in the middle is the
 * house style of exactly the kind of dashboard this must not resemble.
 */
export function SeverityBar({
  counts,
  className,
}: {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (total === 0) {
    return <div className={cn("h-1.5 w-full rounded-full bg-raised", className)} />;
  }
  return (
    <div className={cn("flex h-1.5 w-full gap-px overflow-hidden rounded-full", className)}>
      {SEVERITY_ORDER.map((severity) => {
        const count = counts[severity] ?? 0;
        if (count === 0) return null;
        return (
          <div
            key={severity}
            className={severityStyle(severity).dot}
            style={{ width: `${(count / total) * 100}%` }}
            title={`${count} ${severity}`}
          />
        );
      })}
    </div>
  );
}

/** The counts, laid out as a legend under a bar. */
export function SeverityLegend({
  counts,
  className,
}: {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-x-4 gap-y-1.5", className)}>
      {SEVERITY_ORDER.map((severity) => {
        const count = counts[severity] ?? 0;
        if (count === 0) return null;
        return (
          <div key={severity} className="flex items-center gap-1.5">
            <span className={cn("size-1.5 rounded-full", severityStyle(severity).dot)} aria-hidden />
            <span className="text-[12px] tabular-nums text-ink">{count}</span>
            <span className="text-[12px] capitalize text-ink-faint">{severity}</span>
          </div>
        );
      })}
    </div>
  );
}
