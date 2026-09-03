"use client";

import Link from "next/link";
import { XIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { FindingStatus, Severity } from "@/lib/api";
import { SEVERITY_ORDER, severityStyle } from "./severity";

/**
 * Coarse filters, held in the URL.
 *
 * In the URL rather than in component state so a filtered view can be linked
 * to. "Look at the criticals on checkout-edge" should be a link somebody can
 * paste into an incident channel, not a set of clicks to repeat.
 */
const STATUS_FILTERS: { value: FindingStatus | undefined; label: string }[] = [
  { value: undefined, label: "All" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "ignored", label: "Ignored" },
];

function href(projectId: string, params: Record<string, string | undefined>) {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) search.set(k, v);
  const q = search.toString();
  return `/projects/${projectId}/findings${q ? `?${q}` : ""}`;
}

export function FindingFilters({
  projectId,
  severity,
  status,
  total,
}: {
  projectId: string;
  severity?: Severity;
  status?: FindingStatus;
  total: number;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex items-center gap-1">
        <span className="eyebrow mr-1">Severity</span>
        {SEVERITY_ORDER.map((value) => {
          const active = severity === value;
          return (
            <Link
              key={value}
              href={href(projectId, { severity: active ? undefined : value, status })}
              className={cn(
                "rounded border px-1.5 py-0.5 text-[11px] font-medium capitalize transition-colors duration-100",
                active
                  ? severityStyle(value).chip
                  : "border-line bg-transparent text-ink-faint hover:border-line-strong hover:text-ink-muted",
              )}
            >
              {value}
            </Link>
          );
        })}
      </div>

      <div className="flex items-center gap-1">
        <span className="eyebrow mr-1">Status</span>
        {STATUS_FILTERS.map(({ value, label }) => {
          const active = status === value;
          return (
            <Link
              key={label}
              href={href(projectId, { severity, status: value })}
              className={cn(
                "rounded border px-1.5 py-0.5 text-[11px] font-medium transition-colors duration-100",
                active
                  ? "border-line-strong bg-raised text-ink"
                  : "border-line bg-transparent text-ink-faint hover:border-line-strong hover:text-ink-muted",
              )}
            >
              {label}
            </Link>
          );
        })}
      </div>

      {(severity || status) && (
        <Link
          href={href(projectId, {})}
          className="inline-flex items-center gap-1 text-[12px] text-ink-faint hover:text-ink-muted"
        >
          <XIcon className="size-3" /> Clear
        </Link>
      )}

      <span className="ml-auto text-[12px] tabular-nums text-ink-faint">
        {total} {total === 1 ? "finding" : "findings"}
      </span>
    </div>
  );
}
