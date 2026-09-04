"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { HomeIcon, LayoutGridIcon, LogOutIcon, UsersIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Identity } from "@/lib/api";
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
  { href: "/", label: "Overview", Icon: HomeIcon, exact: true, adminOnly: false },
  { href: "/projects", label: "Projects", Icon: LayoutGridIcon, exact: false, adminOnly: false },
  // Managing accounts is the one thing an ordinary person cannot do at all, so
  // it is the one link worth hiding. Hiding it is a courtesy, not a control:
  // /users checks with the API and reports its refusal, because a link nobody
  // can see is still a URL anybody can type.
  { href: "/users", label: "Access", Icon: UsersIcon, exact: false, adminOnly: true },
];

export function SidebarNav({ identity }: { identity: Identity | null }) {
  const pathname = usePathname();
  const isAdmin = identity?.role === "admin";

  return (
    <aside className="sticky top-0 flex h-screen w-14 shrink-0 flex-col border-r border-line bg-surface md:w-52">
      <div className="flex h-14 items-center justify-center px-0 md:justify-start md:px-4">
        <Wordmark compact />
      </div>

      <div className="hidden px-3 pb-3 md:block">
        <CommandMenuTrigger />
      </div>

      <nav className="flex flex-col gap-0.5 px-3">
        {LINKS.filter((link) => !link.adminOnly || isAdmin).map(({ href, label, Icon, exact }) => {
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

      {/* Who is signed in, and therefore what this session can do. Since
          ADR 033 an action is audited against the person rather than the
          dashboard's own credential, so naming them here is the honest
          equivalent of the old "scans and reads only" note. */}
      <div className="mt-auto shrink-0 space-y-2.5 border-t border-line px-2 py-3 md:px-4">
        {identity && (
          <div className="hidden md:block">
            <p className="truncate text-[11px] font-medium text-ink-muted" title={identity.label}>
              {identity.label}
            </p>
            <p className="text-[11px] leading-snug text-ink-faint">
              {ROLE_NOTE[identity.role] ?? identity.role}
            </p>
          </div>
        )}
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

/**
 * What each role may actually do, in a person's words.
 *
 * `service` appears because a deployment can still run on the dashboard's own
 * token (ADR 029) when no accounts exist -- and a session that is a credential
 * rather than a person should say so rather than borrow a person's label.
 */
const ROLE_NOTE: Record<string, string> = {
  admin: "Administrator — every project, and accounts",
  service: "Scans and reads; triage and policy through the API",
  engineer: "Triage and scans, on your projects",
  viewer: "Read-only, on your projects",
};
