"use client";

import * as React from "react";
import { animate, motion, useMotionValue, useReducedMotion, useTransform } from "motion/react";
import { cn } from "@/lib/utils";

/**
 * A segmented control: one choice from a small, fixed set.
 *
 * A radiogroup rather than a row of buttons, because that is what it is. The
 * distinction is not pedantry -- a screen reader announces "2 of 2 selected"
 * and arrow keys move between options, neither of which a group of buttons
 * gives you.
 *
 * Two techniques worth naming:
 *
 * Roving tabindex. Only the selected option is tabbable; the rest are reached
 * with arrow keys. Tab moves past the whole control, which is what someone
 * filling in the form below it expects.
 *
 * The thumb carries its own copy of the labels, translated inversely so it
 * stays aligned as the thumb slides. That is what makes the label under the
 * thumb read in the inverse colour without cross-fading every label
 * separately, and it means one spring drives the whole transition.
 */
export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  /** Announced to assistive technology in place of the visible label. */
  description?: string;
}

const SPRING = { type: "spring", stiffness: 520, damping: 38, mass: 0.5 } as const;

/** One label cell. The thumb's copy must match this exactly or it will drift. */
const CELL = "px-3 text-[12px] font-medium leading-[26px] tracking-[-0.006em] whitespace-nowrap";

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  label,
  className,
}: {
  options: readonly SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  label: string;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const buttons = React.useRef<(HTMLButtonElement | null)[]>([]);
  const count = Math.max(1, options.length);

  // `1fr`, not `minmax(0, 1fr)`. The latter sets the track's minimum to zero,
  // which lets a column size below its own text -- the grid settled 8px short
  // and clipped "Repository" to "Repositor". `1fr` is `minmax(auto, 1fr)`, so
  // no track goes under its content, and equal fractions then pull every column
  // up to the widest. Equal columns are what let the thumb be positioned as a
  // percentage instead of measured on every resize.
  const columns = `repeat(${count}, 1fr)`;
  // Inside the thumb the total width is already fixed by the track, so equal
  // halves need a minimum of zero -- otherwise each label sizes to its own text
  // and the strip's columns stop lining up with the track's.
  const fixedColumns = `repeat(${count}, minmax(0, 1fr))`;

  // The longest label, rendered invisibly in every cell to set the column
  // width.
  //
  // Equal columns are what let the thumb be positioned as a percentage rather
  // than measured on every resize -- but equal columns sized to *their own*
  // text make the widest label clip under the thumb, which is how "Repository"
  // rendered as "Repositor". Sizing every column to the longest label keeps
  // them equal AND wide enough. `minmax(max-content, 1fr)` looks like the fix
  // and is not: it makes columns unequal, which breaks the percentage.
  const widest = options.reduce((a, b) => (b.label.length > a.length ? b.label : a), "");
  const index = Math.max(0, options.findIndex((o) => o.value === value));

  const position = useMotionValue(index);
  // Percentages resolve against the element's OWN width. The thumb and the
  // strip that carries its labels are both exactly one cell wide (the strip is
  // `inset-0` of the thumb), so an equal-and-opposite 100% cancels the thumb's
  // movement precisely and the label under the thumb stays put.
  //
  // It is the *grid inside* the strip that is `count` cells wide, and it is
  // not transformed at all -- so `count` never enters this arithmetic. Dividing
  // by it here moves the labels half as far as the thumb, measured: an 85px
  // thumb against a 42.5px strip.
  const thumbX = useTransform(position, (v) => `${v * 100}%`);
  const labelsX = useTransform(position, (v) => `${v * -100}%`);

  React.useEffect(() => {
    if (reduced) {
      position.set(index);
      return;
    }
    const controls = animate(position, index, SPRING);
    return () => controls.stop();
  }, [index, position, reduced]);

  function move(to: number) {
    const next = (to + count) % count;
    const option = options[next];
    if (!option) return;
    buttons.current[next]?.focus();
    onChange(option.value);
  }

  function onKeyDown(event: React.KeyboardEvent, i: number) {
    const key = event.key;
    if (key === "ArrowRight" || key === "ArrowDown") {
      event.preventDefault();
      move(i + 1);
    } else if (key === "ArrowLeft" || key === "ArrowUp") {
      event.preventDefault();
      move(i - 1);
    } else if (key === "Home") {
      event.preventDefault();
      move(0);
    } else if (key === "End") {
      event.preventDefault();
      move(count - 1);
    }
  }

  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn(
        "relative inline-block shrink-0 select-none rounded-md border border-line-strong bg-surface p-[3px]",
        className,
      )}
    >
      <div
        className="relative grid w-max"
        style={{ gridTemplateColumns: columns }}
      >
        {/* The sizing layer: invisible, in flow, and the only thing that gives
            this control its width. Every cell renders the LONGEST label, so all
            columns come out equal and none of them clips. */}
        {options.map((option) => (
          <span key={option.value} aria-hidden className={cn(CELL, "invisible")}>
            {widest}
          </span>
        ))}

        {/* The resting labels, under the thumb. */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 grid"
          style={{ gridTemplateColumns: fixedColumns }}
        >
          {options.map((option) => (
            <span key={option.value} className={cn(CELL, "text-center text-ink-muted")}>
              {option.label}
            </span>
          ))}
        </div>

        <motion.div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 left-0 overflow-hidden rounded-[5px] bg-ink"
          style={{ width: `${100 / count}%`, x: thumbX }}
          initial={false}
        >
          <motion.div className="absolute inset-0" style={{ x: labelsX }} initial={false}>
            <div
              className="absolute inset-y-0 left-0 grid"
              style={{ width: `${count * 100}%`, gridTemplateColumns: fixedColumns }}
            >
              {options.map((option) => (
                <span key={option.value} className={cn(CELL, "text-center text-inverse")}>
                  {option.label}
                </span>
              ))}
            </div>
          </motion.div>
        </motion.div>

        {/* The real controls, transparent and on top. */}
        <div className="absolute inset-0 grid" style={{ gridTemplateColumns: fixedColumns }}>
          {options.map((option, i) => (
            <button
              key={option.value}
              ref={(node) => {
                buttons.current[i] = node;
              }}
              type="button"
              role="radio"
              aria-checked={i === index}
              aria-label={option.description ?? option.label}
              tabIndex={i === index ? 0 : -1}
              onClick={() => onChange(option.value)}
              onKeyDown={(event) => onKeyDown(event, i)}
              className="rounded-[5px] outline-none focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent"
            />
          ))}
        </div>
      </div>
    </div>
  );
}
