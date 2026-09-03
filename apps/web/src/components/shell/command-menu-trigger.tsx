"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import * as Dialog from "@radix-ui/react-dialog";
import { SearchIcon, LayoutGridIcon, ActivityIcon, ShieldCheckIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface PaletteProject {
  id: string;
  name: string;
  slug: string;
  environment: string;
  criticality: string;
}

/**
 * The command palette, on ⌘K.
 *
 * Keyboard-first rather than keyboard-accessible: the shortcut is the primary
 * way to move around, and the visible button exists so that people who do not
 * yet know the shortcut can discover it -- which is why the button shows the
 * shortcut rather than hiding it.
 *
 * Projects load when the palette first opens, not on page load. A dashboard
 * that fetches a list nobody asked for on every navigation is the kind of thing
 * that makes an interface feel slow for no benefit.
 */
export function CommandMenuTrigger() {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [projects, setProjects] = React.useState<PaletteProject[] | null>(null);
  // Derived, not stored: "we have opened and have no projects yet" is exactly
  // what loading means here, and a second piece of state could disagree with
  // the first.
  const loading = open && projects === null;

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const requested = React.useRef(false);
  React.useEffect(() => {
    if (!open || requested.current) return;
    requested.current = true;

    let cancelled = false;
    fetch("/api/search")
      .then((r) => r.json())
      .then((body: { projects?: PaletteProject[] }) => {
        if (!cancelled) setProjects(body.projects ?? []);
      })
      .catch(() => {
        // An empty palette rather than a broken one. The reason is not shown:
        // it came from an upstream error and may carry internal detail.
        if (!cancelled) setProjects([]);
      });

    return () => {
      cancelled = true;
    };
  }, [open]);

  const go = React.useCallback(
    (href: string) => {
      setOpen(false);
      router.push(href);
    },
    [router],
  );

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          "flex h-7 w-full items-center gap-2 rounded-md border border-line bg-surface px-2",
          "text-[13px] text-ink-faint transition-colors duration-100",
          "hover:border-line-strong hover:text-ink-muted",
        )}
      >
        <SearchIcon className="size-3.5 shrink-0" />
        <span className="flex-1 text-left">Search</span>
        <kbd className="rounded border border-line-strong bg-raised px-1 py-px font-mono text-[10px] text-ink-faint">
          ⌘K
        </kbd>
      </button>

      <Dialog.Root open={open} onOpenChange={setOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px] data-[state=open]:animate-in data-[state=open]:fade-in-0" />
          <Dialog.Content
            aria-label="Command palette"
            className={cn(
              "fixed left-1/2 top-[18%] z-50 w-full max-w-lg -translate-x-1/2",
              "overflow-hidden rounded-xl border border-line-strong bg-overlay shadow-2xl shadow-black/60",
              "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-98",
            )}
          >
            <Dialog.Title className="sr-only">Search projects and actions</Dialog.Title>
            <Command
              loop
              className="[&_[cmdk-input-wrapper]]:border-b [&_[cmdk-input-wrapper]]:border-line"
            >
              <div className="flex items-center gap-2 border-b border-line px-3">
                <SearchIcon className="size-3.5 shrink-0 text-ink-faint" />
                <Command.Input
                  autoFocus
                  placeholder="Jump to a project, or search…"
                  className="h-10 w-full bg-transparent text-[13px] text-ink outline-none placeholder:text-ink-faint"
                />
              </div>

              <Command.List className="max-h-80 overflow-y-auto p-1.5">
                <Command.Empty className="px-2 py-6 text-center text-[12px] text-ink-faint">
                  {loading ? "Loading…" : "Nothing matches that."}
                </Command.Empty>

                <Command.Group
                  heading="Go to"
                  className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.06em] [&_[cmdk-group-heading]]:text-ink-faint"
                >
                  <PaletteItem onSelect={() => go("/projects")} Icon={LayoutGridIcon}>
                    All projects
                  </PaletteItem>
                </Command.Group>

                {projects && projects.length > 0 && (
                  <Command.Group
                    heading="Projects"
                    className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.06em] [&_[cmdk-group-heading]]:text-ink-faint"
                  >
                    {projects.map((project) => (
                      <PaletteItem
                        key={project.id}
                        value={`${project.name} ${project.slug} ${project.environment}`}
                        onSelect={() => go(`/projects/${project.id}`)}
                        Icon={ShieldCheckIcon}
                        trailing={
                          <span className="font-mono text-[11px] text-ink-faint">
                            {project.environment}
                          </span>
                        }
                      >
                        {project.name}
                      </PaletteItem>
                    ))}
                  </Command.Group>
                )}

                {projects && projects.length > 0 && (
                  <Command.Group
                    heading="Scans"
                    className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.06em] [&_[cmdk-group-heading]]:text-ink-faint"
                  >
                    {projects.slice(0, 5).map((project) => (
                      <PaletteItem
                        key={`scans-${project.id}`}
                        value={`scans ${project.name}`}
                        onSelect={() => go(`/projects/${project.id}/scans`)}
                        Icon={ActivityIcon}
                      >
                        Scans in {project.name}
                      </PaletteItem>
                    ))}
                  </Command.Group>
                )}
              </Command.List>
            </Command>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}

function PaletteItem({
  children,
  onSelect,
  Icon,
  value,
  trailing,
}: {
  children: React.ReactNode;
  onSelect: () => void;
  Icon: typeof SearchIcon;
  value?: string;
  trailing?: React.ReactNode;
}) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className={cn(
        "flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 text-[13px] text-ink-muted",
        "data-[selected=true]:bg-raised data-[selected=true]:text-ink",
      )}
    >
      <Icon className="size-3.5 shrink-0" />
      <span className="flex-1 truncate">{children}</span>
      {trailing}
    </Command.Item>
  );
}
