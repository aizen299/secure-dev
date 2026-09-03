import type { ReactNode } from "react";
import { SidebarNav } from "./sidebar-nav";

/**
 * The application frame: a fixed sidebar and a scrolling content column.
 *
 * The sidebar is narrow (208px) and stays put. Navigation in an operations tool
 * is a constant, not a destination -- collapsing it behind a hamburger would
 * save space a desktop already has and cost an orientation cue a person under
 * pressure relies on.
 */
export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <SidebarNav />
      <div className="flex min-w-0 flex-1 flex-col">{children}</div>
    </div>
  );
}
