"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { HomeIcon, LayoutGridIcon, LogOutIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Wordmark } from "@/components/security/wordmark";
import { CommandMenuTrigger } from "./command-menu-trigger";
import { ThemeToggle } from "./theme";

/**
 * Primary navigation.
 *
 * Deliberately short. The dashboard has one top-level concept -- projects --
 * and everything else is reached through one, so a sidebar listing eight
 * sections would be inventing hierarchy the domain does not have. Depth belongs
 * inside a project, where the tabs are.
 */
const LINKS = [
  { href: "/", label: "Overview", Icon: HomeIcon, exact: true },
  { href: "/projects", label: "Projects", Icon: LayoutGridIcon, exact: false },
];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 flex h-screen w-52 shrink-0 flex-col border-r border-line bg-surface">
      <div className="flex h-14 items-center px-4">
        <Wordmark />
      </div>

      <div className="px-3 pb-3">
        <CommandMenuTrigger />
      </div>

      <nav className="flex flex-col gap-0.5 px-3">
        {LINKS.map(({ href, label, Icon, exact }) => {
          const active = exact ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex h-7 items-center gap-2 rounded-md px-2 text-[13px] transition-colors duration-100",
                active
                  ? "bg-raised font-medium text-ink"
                  : "text-ink-muted hover:bg-raised/60 hover:text-ink",
              )}
            >
              <Icon className="size-3.5 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Stated rather than implied. The dashboard can submit scans but not
          edit a policy or dismiss a finding -- those would be recorded against
          the dashboard rather than a person (ADR 023, ADR 029). */}
      <div className="mt-auto shrink-0 space-y-2.5 border-t border-line px-4 py-3">
        <p className="text-[11px] leading-snug text-ink-faint">
          Scans and reads only. Policy edits and triage go through the API until
          per-user identity lands.
        </p>
        <div className="flex items-center justify-between gap-2">
          <ThemeToggle />
        </div>
        <form method="POST" action="/api/auth/logout">
          <button
            type="submit"
            className="inline-flex items-center gap-1.5 text-[11px] text-ink-faint transition-colors duration-100 hover:text-ink-muted"
          >
            <LogOutIcon className="size-3" /> Sign out
          </button>
        </form>
      </div>
    </aside>
  );
}
