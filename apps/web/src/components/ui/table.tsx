import * as React from "react";
import { cn } from "@/lib/utils";

/**
 * Table primitives tuned for density.
 *
 * 32px rows and 13px text: Linear's proportions rather than the 48px rows a
 * default component library ships. An operator scanning findings needs to see
 * twenty rows without scrolling, and that is a layout decision, not a
 * preference.
 */
export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn("w-full border-collapse text-[13px]", className)} {...props} />
    </div>
  );
}

export function TableHeader({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn("[&_tr]:border-b [&_tr]:border-line", className)} {...props} />;
}

export function TableBody({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn("[&_tr:last-child]:border-0", className)} {...props} />;
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return (
    <tr
      className={cn(
        "border-b border-line transition-colors duration-75",
        "hover:bg-raised/60 data-[state=selected]:bg-accent-muted/40",
        className,
      )}
      {...props}
    />
  );
}

export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "h-8 px-3 text-left align-middle text-[11px] font-medium uppercase tracking-[0.06em] text-ink-faint",
        "whitespace-nowrap first:pl-4 last:pr-4",
        className,
      )}
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn("h-8 px-3 align-middle text-ink first:pl-4 last:pr-4", className)}
      {...props}
    />
  );
}
