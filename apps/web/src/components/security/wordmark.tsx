import { cn } from "@/lib/utils";

/**
 * The mark.
 *
 * A shield built from two overlapping paths rather than an icon-font glyph:
 * it scales, it inherits colour, and it ships no dependency. The notch is the
 * only ornament, and it exists so the shape reads as a shield at 16px rather
 * than as a rounded rectangle.
 */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={cn("size-4", className)} aria-hidden>
      <path
        d="M12 2.5 4.5 5.6v6.2c0 4.6 3.1 8.5 7.5 9.7 4.4-1.2 7.5-5.1 7.5-9.7V5.6L12 2.5Z"
        fill="currentColor"
        fillOpacity="0.16"
      />
      <path
        d="M12 2.5 4.5 5.6v6.2c0 4.6 3.1 8.5 7.5 9.7 4.4-1.2 7.5-5.1 7.5-9.7V5.6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="m8.8 11.9 2.3 2.4 4.1-4.6"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Wordmark({
  className,
  compact,
}: {
  className?: string;
  /** Drops the word below `md`, leaving the mark. For a sidebar that narrows
   *  to icons rather than disappearing on a small window. */
  compact?: boolean;
}) {
  return (
    <span className={cn("flex items-center gap-2", className)}>
      <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-ink text-inverse">
        <Logo className="size-3.5" />
      </span>
      <span
        className={cn(
          "text-[13px] font-semibold tracking-tight text-ink",
          compact && "hidden md:inline",
        )}
      >
        SecureOps
      </span>
    </span>
  );
}
