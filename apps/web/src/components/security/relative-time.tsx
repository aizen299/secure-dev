"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * One clock for the whole page.
 *
 * A table of two hundred findings would otherwise hold two hundred timers to
 * say the same thing. This ticks once a minute -- the smallest unit any label
 * below displays -- and every subscriber recomputes from the same instant, so
 * two rows can never disagree about what "now" is.
 */
const TICK_MS = 60_000;

let listeners: (() => void)[] = [];
let timer: ReturnType<typeof setInterval> | null = null;
let now = 0;

function subscribe(listener: () => void) {
  listeners.push(listener);
  if (timer === null) {
    now = Date.now();
    timer = setInterval(() => {
      now = Date.now();
      for (const l of listeners) l();
    }, TICK_MS);
  }
  return () => {
    listeners = listeners.filter((l) => l !== listener);
    if (listeners.length === 0 && timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };
}

function getSnapshot() {
  if (now === 0) now = Date.now();
  return now;
}

// Zero on the server, which is what makes the server render deterministic:
// reading the clock during render would make the output depend on when it ran,
// producing a hydration mismatch and breaking the purity React relies on.
function getServerSnapshot() {
  return 0;
}

/**
 * A timestamp shown as elapsed time, with the exact value on hover.
 *
 * Both are needed. "3h ago" is what a person reads while triaging; the ISO
 * timestamp is what they quote in an incident channel, and dropping it to make
 * the UI tidier would be a real loss of precision in a security tool.
 *
 * The server emits the absolute date and the browser upgrades it in place, so
 * the label is never wrong -- only briefly terser.
 */
export function RelativeTime({
  value,
  className,
}: {
  value: string;
  className?: string;
}) {
  const reference = React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const then = React.useMemo(() => new Date(value), [value]);
  if (Number.isNaN(then.getTime())) {
    return <span className={cn("text-ink-faint", className)}>—</span>;
  }

  const absolute = then.toISOString();
  const label = reference === 0 ? absolute.slice(0, 10) : elapsed(then.getTime(), reference);

  return (
    <time dateTime={absolute} title={absolute} className={cn(className)}>
      {label}
    </time>
  );
}

function elapsed(then: number, now: number): string {
  const seconds = Math.max(0, (now - then) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)}d ago`;
  return new Date(then).toISOString().slice(0, 10);
}
