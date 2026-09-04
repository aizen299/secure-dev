"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { ArchiveIcon, ArchiveRestoreIcon, LoaderIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Archives a project, or restores one.
 *
 * Archive, not delete. A project's scans, findings and audit trail are
 * security-relevant records and §17 requires them to survive; archiving hides
 * the project from lists and leaves every one of them readable at its URL.
 *
 * Restoring is one click from the same place, which is the point: an archive
 * that cannot be undone from the UI is a delete with a gentler name.
 */
export function ArchiveToggle({ projectId, archived }: { projectId: string; archived: boolean }) {
  const router = useRouter();
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`/api/projects/${projectId}/archive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ archived: !archived }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error?: string };
        setError(body.error ?? "The change was not accepted.");
        return;
      }
      router.refresh();
    } catch {
      setError("The dashboard could not reach its API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      {error && (
        <span role="alert" className="text-[11px] text-fail">
          {error}
        </span>
      )}
      <button
        type="button"
        onClick={toggle}
        disabled={busy}
        title={
          archived
            ? "Show this project in lists again"
            : "Hide from lists. Scans, findings and history stay."
        }
        className={cn(
          "inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-[12px]",
          "transition-colors duration-150 disabled:opacity-40",
          archived
            ? "border-accent/40 text-accent hover:bg-accent/10"
            : "border-line-strong text-ink-muted hover:bg-raised hover:text-ink",
        )}
      >
        {busy ? (
          <LoaderIcon className="size-3 animate-spin" />
        ) : archived ? (
          <ArchiveRestoreIcon className="size-3" />
        ) : (
          <ArchiveIcon className="size-3" />
        )}
        {archived ? "Restore" : "Archive"}
      </button>
    </div>
  );
}
