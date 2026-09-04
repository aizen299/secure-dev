import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One number with its label.
 *
 * The label sits above the value in small caps, which lets a row of these read
 * as a single band of information rather than as a row of competing cards. No
 * borders between them: alignment does that work, and a border per metric would
 * turn four facts into four objects.
 *
 * `hint` is for context that is always true of the number. `trend` is for a
 * change, and it is deliberately a separate slot so that a caller has to have
 * an actual comparison in hand to fill it -- there is no "trend" prop that
 * quietly renders zero when nothing was measured. A dashboard that invents a
 * direction is worse than one that shows none.
 */
export function Metric({
  label,
  value,
  hint,
  trend,
  tone,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  trend?: ReactNode;
  tone?: "default" | "critical" | "warn" | "good" | "faint";
  className?: string;
}) {
  return (
    <div
      className={cn(
        "group/metric relative -mx-2 rounded-md px-2 py-1.5",
        "transition-colors duration-150 hover:bg-raised/40",
        className,
      )}
    >
      <p className="eyebrow transition-colors duration-150 group-hover/metric:text-ink-muted">
        {label}
      </p>
      <p
        className={cn(
          "mt-1.5 text-[24px] font-medium leading-none tabular-nums tracking-tight",
          tone === "critical" && "text-critical",
          tone === "warn" && "text-warn",
          tone === "good" && "text-pass",
          tone === "faint" && "text-ink-faint",
          (!tone || tone === "default") && "text-ink",
        )}
      >
        {value}
      </p>
      {(trend || hint) && (
        <div className="mt-1.5 space-y-0.5">
          {trend}
          {hint && <p className="text-[11px] leading-snug text-ink-faint">{hint}</p>}
        </div>
      )}
    </div>
  );
}

/**
 * A measured change.
 *
 * Takes a rendered comparison, never a bare number to guess a direction from.
 * The neutral tone is the default because most changes on this dashboard are
 * facts rather than good news -- "8 added this week" is not an improvement or a
 * regression, and colouring it as either would be editorialising.
 */
export function Trend({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "good" | "bad";
}) {
  return (
    <p
      className={cn(
        "flex items-center gap-1 text-[11px] leading-snug tabular-nums",
        tone === "good" && "text-pass",
        tone === "bad" && "text-critical",
        tone === "neutral" && "text-ink-muted",
      )}
    >
      {children}
    </p>
  );
}
