import { CheckIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Verdict } from "@/lib/api";

const VERDICT_STYLE: Record<Verdict, { chip: string; Icon: typeof CheckIcon; label: string }> = {
  pass: { chip: "border-pass/25 bg-pass-dim text-pass", Icon: CheckIcon, label: "Pass" },
  warn: { chip: "border-warn/25 bg-warn-dim text-warn", Icon: TriangleAlertIcon, label: "Warn" },
  fail: { chip: "border-fail/25 bg-fail-dim text-fail", Icon: XIcon, label: "Fail" },
};

/**
 * The gate verdict.
 *
 * Carries an icon as well as a colour, because this is the value most likely to
 * be read at a glance and under time pressure -- and the one where colour alone
 * would fail a colour-blind reader on the distinction that matters most.
 */
export function VerdictBadge({
  verdict,
  size = "default",
  className,
}: {
  verdict: Verdict;
  size?: "default" | "lg";
  className?: string;
}) {
  const { chip, Icon, label } = VERDICT_STYLE[verdict] ?? VERDICT_STYLE.fail;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border font-medium leading-none",
        size === "lg" ? "px-2.5 py-1.5 text-[13px]" : "px-1.5 py-0.5 text-[11px]",
        chip,
        className,
      )}
    >
      <Icon className={size === "lg" ? "size-3.5" : "size-3"} aria-hidden />
      {label}
    </span>
  );
}
