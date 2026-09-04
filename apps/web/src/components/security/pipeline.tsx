"use client";

import { motion, useReducedMotion } from "motion/react";
import { cn } from "@/lib/utils";

/**
 * The pipeline, drawn.
 *
 * §2 insists SecureOps is not "a dashboard that runs several CLI tools" -- the
 * value is the intelligence layer. This says so in the shape of the thing: five
 * scanners converging into one line, which then passes through four stages. A
 * row of scanner logos would claim the opposite.
 *
 * The drawing is the argument, so it is drawn rather than listed. The dash
 * travelling along the trunk is the only ornament, and it exists because the
 * diagram's whole claim is that data *moves* through these stages.
 */
const SOURCES = ["Secrets", "SBOM", "Deps", "Code", "Config"];
const STAGES = [
  { label: "Normalize", detail: "one finding model" },
  { label: "Correlate", detail: "one problem, seen twice" },
  { label: "Score", detail: "risk in context" },
  { label: "Remediate", detail: "ranked by risk removed" },
  { label: "Gate", detail: "pass, warn, or fail" },
];

export function Pipeline({ className }: { className?: string }) {
  const reduced = useReducedMotion();

  return (
    <div className={cn("overflow-hidden rounded-lg border border-line bg-panel", className)}>
      <div className="relative px-4 pt-4 pb-1">
        <svg viewBox="0 0 640 108" className="h-24 w-full" role="img"
             aria-label="Five scanners converge into one finding model, then normalize, correlate, score, remediate and gate">
          <defs>
            <linearGradient id="trunk" x1="0" x2="1">
              <stop offset="0%" stopColor="var(--color-line-strong)" />
              <stop offset="55%" stopColor="var(--color-accent)" stopOpacity="0.55" />
              <stop offset="100%" stopColor="var(--color-pass)" stopOpacity="0.7" />
            </linearGradient>
          </defs>

          {/* Five sources fanning into one trunk: the convergence is the claim. */}
          {SOURCES.map((label, i) => {
            const y = 12 + i * 20;
            return (
              <g key={label}>
                <motion.path
                  d={`M18 ${y} H92 Q126 ${y} 126 54`}
                  fill="none"
                  stroke="var(--color-line-strong)"
                  strokeWidth="1"
                  initial={reduced ? undefined : { pathLength: 0, opacity: 0 }}
                  animate={reduced ? undefined : { pathLength: 1, opacity: 1 }}
                  transition={{ duration: 0.7, delay: i * 0.07, ease: [0.16, 1, 0.3, 1] }}
                />
                <circle cx="14" cy={y} r="2.5" fill="var(--color-ink-faint)" />
                <text x="24" y={y + 3.4} className="fill-ink-faint" style={{ fontSize: 8.5 }}>
                  {label}
                </text>
              </g>
            );
          })}

          <motion.line
            x1="126" y1="54" x2="620" y2="54"
            stroke="url(#trunk)" strokeWidth="1.5"
            initial={reduced ? undefined : { pathLength: 0 }}
            animate={reduced ? undefined : { pathLength: 1 }}
            transition={{ duration: 0.8, delay: 0.35, ease: [0.16, 1, 0.3, 1] }}
          />

          {/* One dash travelling the trunk. The diagram's claim is that data
              moves through these stages, so exactly one thing moves. */}
          {!reduced && (
            <motion.circle
              r="2.6" cy="54" fill="var(--color-accent)"
              initial={{ cx: 126, opacity: 0 }}
              animate={{ cx: [126, 620], opacity: [0, 1, 1, 0] }}
              transition={{ duration: 3.4, delay: 1.1, repeat: Infinity, repeatDelay: 1.6, ease: "linear" }}
            />
          )}

          {STAGES.map((stage, i) => {
            const x = 150 + i * 96;
            return (
              <motion.g
                key={stage.label}
                initial={reduced ? undefined : { opacity: 0, y: 4 }}
                animate={reduced ? undefined : { opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: 0.55 + i * 0.09 }}
              >
                <circle cx={x} cy="54" r="4" fill="var(--color-base)"
                        stroke={i === STAGES.length - 1 ? "var(--color-pass)" : "var(--color-accent)"}
                        strokeWidth="1.6" />
                <text x={x} y="76" textAnchor="middle" className="fill-ink" style={{ fontSize: 9.5, fontWeight: 500 }}>
                  {stage.label}
                </text>
                <text x={x} y="88" textAnchor="middle" className="fill-ink-faint" style={{ fontSize: 7.5 }}>
                  {stage.detail}
                </text>
              </motion.g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

/**
 * A faint dot grid behind the header.
 *
 * Texture, not decoration with a message: it gives the top of the page
 * somewhere to sit without introducing a colour or a shape that competes with
 * severity. Masked so it fades out rather than ending on a line.
 */
export function DotGrid({ className }: { className?: string }) {
  return (
    <div
      aria-hidden
      className={cn("pointer-events-none absolute inset-0 -z-10 opacity-[0.5]", className)}
      style={{
        backgroundImage: "radial-gradient(var(--color-line-strong) 1px, transparent 1px)",
        backgroundSize: "22px 22px",
        maskImage: "radial-gradient(ellipse 70% 100% at 20% 0%, black 20%, transparent 75%)",
        WebkitMaskImage: "radial-gradient(ellipse 70% 100% at 20% 0%, black 20%, transparent 75%)",
      }}
    />
  );
}
