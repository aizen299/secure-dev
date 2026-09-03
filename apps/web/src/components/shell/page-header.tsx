import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * The page header band.
 *
 * Sticky, 56px, hairline-bottomed. It matches the sidebar's header height so
 * the two line up across the fold -- the kind of alignment nobody notices when
 * it is right and everybody feels when it is wrong.
 */
export function PageHeader({
  title,
  eyebrow,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <header
      className={cn(
        "sticky top-0 z-30 border-b border-line bg-base/85 backdrop-blur-md",
        className,
      )}
    >
      <div className="flex h-14 items-center gap-4 px-6">
        <div className="min-w-0 flex-1">
          {eyebrow && <div className="mb-0.5 text-[11px] text-ink-faint">{eyebrow}</div>}
          <h1 className="truncate text-[15px] font-medium tracking-tight text-ink">{title}</h1>
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

/** The content column. One max width, one padding scale, defined once. */
export function PageBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("mx-auto w-full max-w-[1400px] px-6 py-6", className)}>{children}</div>;
}
