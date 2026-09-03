"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

/**
 * In-project navigation.
 *
 * The order is the pipeline order -- posture, then the findings behind it, then
 * the issues correlation drew from them, then what to do, then the scans that
 * produced it all. A reader moving left to right is following the same path the
 * platform took (§2).
 */
const TABS = [
  { segment: "", label: "Overview" },
  { segment: "findings", label: "Findings" },
  { segment: "issues", label: "Issues" },
  { segment: "remediation", label: "Remediation" },
  { segment: "scans", label: "Scans" },
];

export function ProjectTabs({ projectId }: { projectId: string }) {
  const pathname = usePathname();
  const base = `/projects/${projectId}`;

  return (
    <nav className="flex items-center gap-1 px-6" aria-label="Project sections">
      {TABS.map(({ segment, label }) => {
        const href = segment ? `${base}/${segment}` : base;
        const active = segment ? pathname.startsWith(href) : pathname === base;
        return (
          <Link
            key={label}
            href={href}
            className={cn(
              "relative -mb-px flex h-8 items-center px-2 text-[13px] transition-colors duration-100",
              "after:absolute after:inset-x-2 after:bottom-0 after:h-px",
              active
                ? "font-medium text-ink after:bg-ink"
                : "text-ink-faint hover:text-ink-muted after:bg-transparent",
            )}
          >
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
