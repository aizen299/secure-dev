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
    <aside className="sticky top-0 flex h-screen w-14 shrink-0 flex-col border-r border-line bg-surface md:w-52">
      <div className="flex h-14 items-center justify-center px-0 md:justify-start md:px-4">
        <Wordmark compact />
      </div>

      <div className="hidden px-3 pb-3 md:block">
        <CommandMenuTrigger />
      </div>

      <nav className="flex flex-col gap-0.5 px-3">
        {LINKS.map(({ href, label, Icon, exact }) => {
          const active = exact ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "group relative flex h-8 items-center justify-center gap-2 rounded-md text-[13px]",
                "md:h-7 md:justify-start md:px-2",
                "transition-colors duration-150",
                active
                  ? "bg-raised font-medium text-ink"
                  : "text-ink-muted hover:bg-raised/60 hover:text-ink",
              )}
            >
              {/* A short accent rule on the active item. Two signals rather than
                  one, because a background shift alone is easy to lose against
                  a dark surface -- and the current section is the one thing in
                  this sidebar that has to be unambiguous. */}
              <span
                aria-hidden
                className={cn(
                  "absolute left-0 top-1/2 h-3.5 w-0.5 -translate-y-1/2 rounded-r-full bg-accent",
                  "transition-opacity duration-150",
                  active ? "opacity-100" : "opacity-0",
                )}
              />
              <Icon
                className={cn(
                  "size-3.5 shrink-0 transition-colors duration-150",
                  active ? "text-accent" : "text-ink-faint group-hover:text-ink-muted",
                )}
              />
              <span className="hidden md:inline">{label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Stated rather than implied. The dashboard can submit scans but not
          edit a policy or dismiss a finding -- those would be recorded against
          the dashboard rather than a person (ADR 023, ADR 029). */}
      <div className="mt-auto shrink-0 space-y-2.5 border-t border-line px-2 py-3 md:px-4">
        <p className="hidden text-[11px] leading-snug text-ink-faint md:block">
          Scans and reads only. Policy edits and triage go through the API until
          per-user identity lands.
        </p>
        <div className="flex items-center justify-center gap-2 md:justify-between">
          <ThemeToggle />
        </div>
        <form method="POST" action="/api/auth/logout">
          <button
            type="submit"
            className="inline-flex w-full items-center justify-center gap-1.5 text-[11px] text-ink-faint transition-colors duration-100 hover:text-ink-muted md:w-auto md:justify-start"
            title="Sign out"
          >
            <LogOutIcon className="size-3" />
            <span className="hidden md:inline">Sign out</span>
          </button>
        </form>
      </div>
    </aside>
  );
}
