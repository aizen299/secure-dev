import { cn } from "@/lib/utils";
import type { FindingStatus, ScanStatus } from "@/lib/api";

/**
 * Finding lifecycle state.
 *
 * Deliberately quiet. A finding's status is context for its severity, not a
 * competing signal, so these are greyscale with one exception: `open` is left
 * unmuted because it is the state that means "still your problem".
 */
const FINDING_STATUS_STYLE: Record<FindingStatus, string> = {
  open: "border-line-strong bg-raised text-ink",
  reopened: "border-high/25 bg-high-dim text-high",
  acknowledged: "border-line-strong bg-raised text-ink-muted",
  in_progress: "border-accent-muted bg-accent-muted text-accent",
  resolved: "border-pass/20 bg-pass-dim text-pass",
  false_positive: "border-line-strong bg-raised text-ink-faint",
  ignored: "border-line-strong bg-raised text-ink-faint",
};

const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Open",
  reopened: "Reopened",
  acknowledged: "Acknowledged",
  in_progress: "In progress",
  resolved: "Resolved",
  false_positive: "False positive",
  ignored: "Ignored",
};

export function FindingStatusBadge({
  status,
  className,
}: {
  status: FindingStatus;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium leading-none",
        FINDING_STATUS_STYLE[status] ?? FINDING_STATUS_STYLE.open,
        className,
      )}
    >
      {FINDING_STATUS_LABEL[status] ?? status}
    </span>
  );
}

/**
 * Scan state.
 *
 * `partial` is styled as a warning rather than as a neutral state, because §13
 * turns on the distinction: a partial scan must never read as a successful
 * complete one, and the interface is where that promise is either kept or
 * quietly broken.
 */
const SCAN_STATUS_STYLE: Record<ScanStatus, string> = {
  queued: "border-line-strong bg-raised text-ink-faint",
  running: "border-accent-muted bg-accent-muted text-accent",
  partial: "border-warn/25 bg-warn-dim text-warn",
  completed: "border-pass/20 bg-pass-dim text-pass",
  failed: "border-fail/25 bg-fail-dim text-fail",
  cancelled: "border-line-strong bg-raised text-ink-faint",
};

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-medium capitalize leading-none",
        SCAN_STATUS_STYLE[status] ?? SCAN_STATUS_STYLE.queued,
        className,
      )}
    >
      {status === "running" && (
        <span className="size-1.5 animate-pulse rounded-full bg-accent" aria-hidden />
      )}
      {status}
    </span>
  );
}
