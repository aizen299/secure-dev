"use client";

import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  // Height and radius are small on purpose. Large pill buttons read as
  // marketing; this is an operator's tool.
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-[13px] font-medium transition-colors duration-100 disabled:pointer-events-none disabled:opacity-40 [&_svg]:size-3.5 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-ink text-inverse hover:bg-ink/90",
        outline:
          "border border-line-strong bg-transparent text-ink hover:bg-raised hover:border-line-strong",
        ghost: "text-ink-muted hover:bg-raised hover:text-ink",
        subtle: "bg-raised text-ink hover:bg-overlay",
        danger: "bg-critical-dim text-critical hover:bg-critical-dim/70",
      },
      size: {
        sm: "h-7 px-2.5",
        default: "h-8 px-3",
        lg: "h-9 px-4",
        icon: "size-8 p-0",
        "icon-sm": "size-7 p-0",
      },
    },
    defaultVariants: { variant: "outline", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp ref={ref} className={cn(buttonVariants({ variant, size, className }))} {...props} />
    );
  },
);
Button.displayName = "Button";

export { buttonVariants };
