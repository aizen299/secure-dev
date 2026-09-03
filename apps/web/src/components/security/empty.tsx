import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * An empty state that says what is true and what to do next.
 *
 * Never "No data". A project with no scans, a project whose scans found
 * nothing, and a project the dashboard could not read are three different
 * situations, and collapsing them into one grey box is how an operator comes to
 * distrust the whole screen.
 */
export function EmptyState({
  title,
  description,
  icon,
  action,
  tone = "neutral",
  className,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
  tone?: "neutral" | "good" | "warn";
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 px-6 py-12 text-center",
        className,
      )}
    >
      {icon && (
        <div
          className={cn(
            "mb-1 flex size-9 items-center justify-center rounded-lg border",
            tone === "good" && "border-pass/20 bg-pass-dim text-pass",
            tone === "warn" && "border-warn/25 bg-warn-dim text-warn",
            tone === "neutral" && "border-line bg-raised text-ink-faint",
          )}
        >
          {icon}
        </div>
      )}
      <p className="text-[13px] font-medium text-ink">{title}</p>
      {description && (
        <p className="max-w-sm text-[12px] leading-relaxed text-ink-faint">{description}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
