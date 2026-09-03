import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  // Squared-off rather than pill: a pill reads as a marketing tag, a small
  // radius reads as a state label.
  "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium leading-none whitespace-nowrap",
  {
    variants: {
      variant: {
        neutral: "border-line-strong bg-raised text-ink-muted",
        outline: "border-line-strong bg-transparent text-ink-muted",
        accent: "border-accent-muted bg-accent-muted text-accent",
      },
    },
    defaultVariants: { variant: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
