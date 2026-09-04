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
