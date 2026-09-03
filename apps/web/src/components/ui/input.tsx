import * as React from "react";
import { cn } from "@/lib/utils";

export const Input = React.forwardRef<
  HTMLInputElement,
  React.InputHTMLAttributes<HTMLInputElement>
>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "h-8 w-full rounded-md border border-line-strong bg-surface px-2.5 text-[13px] text-ink",
      "placeholder:text-ink-faint focus-visible:border-accent focus-visible:outline-none",
      "transition-colors duration-100 disabled:opacity-40",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";
