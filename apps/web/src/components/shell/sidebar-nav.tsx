"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutGridIcon, ShieldIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { CommandMenuTrigger } from "./command-menu-trigger";

/**
 * Primary navigation.
 *
 * Deliberately short. The dashboard has one top-level concept -- projects --
 * and everything else is reached through one, so a sidebar listing eight
 * sections would be inventing hierarchy the domain does not have. Depth belongs
 * inside a project, where the tabs are.
 */
const LINKS = [{ href: "/projects", label: "Projects", Icon: LayoutGridIcon }];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 flex h-screen w-52 shrink-0 flex-col border-r border-line bg-surface">
      <div className="flex h-14 items-center gap-2 px-4">
        <div className="flex size-6 items-center justify-center rounded bg-ink text-base">
          <ShieldIcon className="size-3.5" strokeWidth={2.5} />
        </div>
        <span className="text-[13px] font-semibold tracking-tight text-ink">SecureOps</span>
      </div>

      <div className="px-3 pb-3">
        <CommandMenuTrigger />
      </div>

      <nav className="flex flex-col gap-0.5 px-3">
        {LINKS.map(({ href, label, Icon }) => {
          const active = pathname === href || pathname.startsWith(`${href}/`);
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

      {/* Stated rather than implied. The dashboard holds a viewer credential
          and cannot change anything; a reader should know that before going
          looking for a button that does not exist (ADR 023). */}
      <div className="mt-auto shrink-0 border-t border-line px-4 py-3">
        <p className="text-[11px] leading-snug text-ink-faint">
          Read-only. Triage and policy changes go through the API until
          per-user identity lands.
        </p>
      </div>
    </aside>
  );
}
