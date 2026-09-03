import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One number with its label.
 *
 * The label sits above the value in small caps, which lets a row of these read
 * as a single band of information rather than as a row of competing cards. No
 * borders between them: alignment does that work.
 */
export function Metric({
  label,
  value,
  hint,
  tone,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "critical" | "warn" | "good" | "faint";
  className?: string;
}) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <p className="eyebrow">{label}</p>
      <p
        className={cn(
          "text-[22px] font-medium leading-none tabular-nums tracking-tight",
          tone === "critical" && "text-critical",
          tone === "warn" && "text-warn",
          tone === "good" && "text-pass",
          tone === "faint" && "text-ink-faint",
          (!tone || tone === "default") && "text-ink",
        )}
      >
        {value}
      </p>
      {hint && <p className="text-[12px] leading-snug text-ink-faint">{hint}</p>}
    </div>
  );
}
