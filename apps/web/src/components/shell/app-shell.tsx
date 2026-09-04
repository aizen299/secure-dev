import type { ReactNode } from "react";
import type { Identity } from "@/lib/api";
import { SidebarNav } from "./sidebar-nav";

/**
 * The application frame: a fixed sidebar and a scrolling content column.
 *
 * The sidebar is narrow (208px) and stays put. Navigation in an operations tool
 * is a constant, not a destination -- collapsing it behind a hamburger would
 * save space a desktop already has and cost an orientation cue a person under
 * pressure relies on.
 *
 * Below `md` it narrows to icons rather than disappearing, which keeps that cue
 * while giving the content column back the width it needs. At 208px on a narrow
 * window the body text wrapped to roughly one word per line.
 */
export function AppShell({ children, identity }: { children: ReactNode; identity?: Identity | null }) {
  return (
    <div className="flex min-h-screen">
      <SidebarNav identity={identity ?? null} />
      <div className="flex min-w-0 flex-1 flex-col">{children}</div>
    </div>
  );
}
