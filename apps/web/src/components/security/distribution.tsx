"use client";

import * as React from "react";
import { motion, useReducedMotion } from "motion/react";
import { cn } from "@/lib/utils";

/**
 * A proportional band: parts of a whole, drawn to scale.
 *
 * Not a chart library. Recharts is a dependency of this app and this is not the
 * place for it -- these are stacked proportions with a legend, which is CSS,
 * and pulling a charting runtime into the first paint of the overview to draw
 * five divs would be paying a bundle for an abstraction that adds nothing.
 * Recharts earns its place where there are axes, scales and a time series.
 *
 * Every segment here is a count of real rows. A band with nothing in it renders
 * as an empty track and says so, rather than being padded to look populated.
 */
export interface Segment {
  label: string;
  value: number;
  /** A token name from the severity or verdict ramp -- meaning, not decoration. */
  color: string;
  hint?: string;
}

const EASE = [0.16, 1, 0.3, 1] as const;

export function Distribution({
  title,
  segments,
  total,
  empty,
  className,
}: {
  title: string;
  segments: Segment[];
  /** The denominator. Passed rather than summed so a band can be a share of
   *  something larger than the segments shown. */
  total: number;
  empty: string;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const [hovered, setHovered] = React.useState<string | null>(null);
  const present = segments.filter((s) => s.value > 0);

  return (
    <div className={cn("space-y-2.5", className)}>
      <div className="flex items-baseline justify-between gap-3">
        <span className="eyebrow">{title}</span>
        <span className="text-[11px] tabular-nums text-ink-faint">
          {total} {total === 1 ? "project" : "projects"}
        </span>
      </div>

      <div
        className="flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full bg-raised"
        role="img"
        aria-label={
          present.length === 0
            ? empty
            : present.map((s) => `${s.value} ${s.label}`).join(", ")
        }
        onPointerLeave={() => setHovered(null)}
      >
        {present.map((segment, i) => (
          <motion.div
            key={segment.label}
            className="h-full rounded-full"
            style={{ backgroundColor: `var(--color-${segment.color})` }}
            initial={reduced ? false : { width: 0 }}
            animate={{
              width: `${(segment.value / Math.max(1, total)) * 100}%`,
              opacity: hovered === null || hovered === segment.label ? 1 : 0.3,
            }}
            transition={{ duration: 0.5, ease: EASE, delay: reduced ? 0 : 0.1 + i * 0.05 }}
            onPointerEnter={() => setHovered(segment.label)}
          />
        ))}
      </div>

      {present.length === 0 ? (
        <p className="text-[11px] leading-relaxed text-ink-faint">{empty}</p>
      ) : (
        <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
          {present.map((segment) => (
            <li
              key={segment.label}
              className="flex items-center gap-1.5"
              onPointerEnter={() => setHovered(segment.label)}
              onPointerLeave={() => setHovered(null)}
            >
              <span
                aria-hidden
                className="size-1.5 shrink-0 rounded-full transition-transform duration-150"
                style={{
                  backgroundColor: `var(--color-${segment.color})`,
                  transform: hovered === segment.label ? "scale(1.5)" : "scale(1)",
                }}
              />
              <span
                className={cn(
                  "text-[11px] transition-colors duration-150",
                  hovered === segment.label ? "text-ink" : "text-ink-muted",
                )}
              >
                {segment.label}
              </span>
              <span className="text-[11px] tabular-nums text-ink-faint">{segment.value}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * A project's score, as a bar against the same 0-100 scale every other row uses.
 *
 * Shared scale is the whole point: a bar per row normalised to the worst score
 * in view would make the top row full-width on every dashboard, including one
 * where the worst project scores 4. The ranking would look identical whether
 * the estate was on fire or fine.
 */
export function ScoreBar({ score, color, className }: { score: number; color: string; className?: string }) {
  const reduced = useReducedMotion();
  return (
    <span className={cn("block h-0.5 w-full overflow-hidden rounded-full bg-raised", className)}>
      <motion.span
        className="block h-full rounded-full"
        style={{ backgroundColor: `var(--color-${color})` }}
        initial={reduced ? false : { width: 0 }}
        animate={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        transition={{ duration: 0.6, ease: EASE, delay: reduced ? 0 : 0.15 }}
      />
    </span>
  );
}
