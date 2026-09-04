"use client";

import * as React from "react";
import { motion, useMotionValue, useSpring, useReducedMotion } from "motion/react";
import { cn } from "@/lib/utils";

/** One easing curve for the whole interface, so motion feels like one system. */
const EASE = [0.16, 1, 0.3, 1] as const;

/**
 * Reveals its children once, on entry.
 *
 * Short and small: 260ms and a six-pixel rise. Motion here confirms that
 * content arrived; it never announces itself. Anything longer reads as lag in
 * a tool people open twenty times a day.
 *
 * Honours prefers-reduced-motion by rendering the final state immediately --
 * not a slower animation, no animation.
 */
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: React.ReactNode;
  delay?: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  if (reduced) return <div className={className}>{children}</div>;

  // Animates on mount rather than on scrolling into view.
  //
  // An in-view trigger holds content at opacity 0 until an IntersectionObserver
  // fires, which means any environment where it does not fire shows a blank
  // page -- and a security dashboard that renders nothing is a far worse
  // outcome than one that animates something already on screen. These pages
  // are short enough that the distinction buys nothing anyway.
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.26, ease: EASE, delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/** Reveals a list, each item a beat behind the last. */
export function Stagger({
  children,
  className,
  step = 0.04,
}: {
  children: React.ReactNode;
  className?: string;
  step?: number;
}) {
  const reduced = useReducedMotion();
  if (reduced) return <div className={className}>{children}</div>;

  return (
    <motion.div
      initial="hidden"
      animate="shown"
      variants={{ shown: { transition: { staggerChildren: step } } }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const reduced = useReducedMotion();
  if (reduced) return <div className={className}>{children}</div>;

  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 4 },
        shown: { opacity: 1, y: 0, transition: { duration: 0.24, ease: EASE } },
      }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/**
 * A number that counts up to its value.
 *
 * Spring-driven rather than linear, so it decelerates into place the way a
 * physical dial would. It renders the true value immediately under reduced
 * motion, and it always ends on the exact figure -- a counter that lands one
 * off is worse than no counter at all in a tool where the number is the point.
 */
export function Counter({
  value,
  decimals = 0,
  className,
}: {
  value: number;
  decimals?: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const [animated, setAnimated] = React.useState(0);

  const raw = useMotionValue(0);
  const spring = useSpring(raw, { stiffness: 90, damping: 20, mass: 0.7 });

  React.useEffect(() => {
    if (reduced) return;
    raw.set(value);
    const stop = spring.on("change", setAnimated);
    // Snap to the exact value once the spring settles: the figure on screen
    // has to be the figure, not an approximation of it. A risk score that
    // lands on 81.6 when the engine said 81.7 is a wrong number.
    const settle = setTimeout(() => setAnimated(value), 900);
    return () => {
      stop();
      clearTimeout(settle);
    };
  }, [value, raw, spring, reduced]);

  // Under reduced motion the true value is rendered directly -- no state, no
  // effect, nothing to settle.
  const shown = reduced ? value : animated;

  return (
    <span className={cn("tabular-nums", className)}>
      {shown.toFixed(decimals)}
    </span>
  );
}

/**
 * Two or more states in one place, only one of them visible.
 *
 * Every state is rendered and stacked; the inactive ones are transparent,
 * inert, and hidden from assistive technology. Nothing mounts or unmounts, so
 * there is no presence bookkeeping to go wrong.
 *
 * Deliberately CSS transitions rather than an `AnimatePresence` swap, and the
 * reason is about the failure mode rather than the happy path.
 *
 * Presence-based swapping removes the outgoing element when its exit animation
 * reports that it finished. Where animation frames do not run -- a backgrounded
 * tab, a throttled or headless context -- that report never arrives, and the
 * outgoing element stays visible while the new one sits at its `initial`
 * values. Observed here: the heading kept the old mode's text while the
 * placeholder, the label and the button had all switched. Which is precisely
 * the contradiction this component exists to make impossible.
 *
 * A class change cannot fail that way. If the transition never runs, both
 * elements still land in the right end state instantly -- which is also exactly
 * what prefers-reduced-motion should do, and globals.css already handles it, so
 * there is no reduced-motion branch in here.
 *
 * The container must size itself -- these children are absolutely positioned
 * and contribute no height.
 */
export function CrossFade<T extends string>({
  active,
  states,
  render,
  className,
  id,
  "aria-hidden": ariaHidden,
}: {
  active: T;
  states: readonly T[];
  render: (state: T) => React.ReactNode;
  className?: string;
  /** For an `aria-labelledby` that must point at something stable. */
  id?: string;
  "aria-hidden"?: boolean;
}) {
  return (
    <div id={id} aria-hidden={ariaHidden} className={cn("relative", className)}>
      {states.map((state) => {
        const shown = state === active;
        return (
          <div
            key={state}
            aria-hidden={!shown}
            inert={!shown}
            className={cn(
              "absolute inset-0 transition-[opacity,transform] duration-200 ease-out",
              shown ? "translate-y-0 opacity-100" : "pointer-events-none translate-y-1 opacity-0",
            )}
          >
            {render(state)}
          </div>
        );
      })}
    </div>
  );
}
