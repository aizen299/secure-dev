"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRightIcon, LoaderIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanProgress } from "./scan-progress";

/**
 * Paste a repository URL, get a scan.
 *
 * The whole point is that this replaces a multi-line curl with a token pulled
 * out of .env. It exists only because the dashboard authenticates now
 * (ADR 029) -- an anonymous page able to queue clones is a way to make the
 * worker fetch arbitrary URLs.
 *
 * The URL is not validated here beyond an obvious shape check. The API applies
 * the address policy and the argument-injection defences, and a second,
 * weaker copy of those rules in the browser is a place for the two to
 * disagree. What the API rejects is shown verbatim, because "scheme must be
 * https" is exactly what the person typing needs to read.
 */
export function ScanBar({ className }: { className?: string }) {
  const router = useRouter();
  const [url, setUrl] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [running, setRunning] = React.useState<{ scanId: string; projectId: string } | null>(null);

  const onDone = React.useCallback(
    (projectId: string) => {
      setRunning(null);
      router.push(`/projects/${projectId}`);
      router.refresh();
    },
    [router],
  );

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);

    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repository_url: url.trim() }),
      });
      const body = (await response.json()) as {
        project_id?: string;
        scan_id?: string;
        error?: string;
      };

      if (!response.ok || !body.project_id || !body.scan_id) {
        setError(body.error ?? "The scan could not be submitted.");
        return;
      }
      setUrl("");
      // Stay here and show the scan working. Navigating immediately would put
      // the person on a project page whose every panel says "no data yet",
      // which is the least informative moment of the whole run.
      setRunning({ scanId: body.scan_id, projectId: body.project_id });
    } catch {
      setError("The dashboard could not reach its API.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={cn("space-y-2.5", className)}>
      <form onSubmit={submit} className="flex gap-2">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://github.com/owner/repository"
          aria-label="Repository URL to scan"
          spellCheck={false}
          className={cn(
            "h-9 flex-1 rounded-md border border-line-strong bg-surface px-3",
            "font-mono text-[13px] text-ink placeholder:text-ink-faint",
            "focus-visible:border-accent focus-visible:outline-none",
            "transition-colors duration-100",
          )}
        />
        <button
          type="submit"
          disabled={busy || running !== null || url.trim() === ""}
          className={cn(
            "inline-flex h-9 shrink-0 items-center gap-1.5 rounded-md bg-ink px-3.5",
            "text-[13px] font-medium text-base transition-colors duration-100",
            "hover:bg-ink/90 disabled:opacity-40",
          )}
        >
          {busy ? <LoaderIcon className="size-3.5 animate-spin" /> : <ArrowRightIcon className="size-3.5" />}
          {busy ? "Submitting" : "Scan"}
        </button>
      </form>

      <AnimatePresence mode="wait">
        {error && (
          <motion.p
            key="error"
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="rounded-md border border-fail/25 bg-fail-dim px-3 py-2 text-[12px] leading-relaxed text-fail"
          >
            {error}
          </motion.p>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {running && (
          <ScanProgress
            key={running.scanId}
            scanId={running.scanId}
            projectId={running.projectId}
            onDone={onDone}
          />
        )}
      </AnimatePresence>

      <p className="text-[11px] leading-relaxed text-ink-faint">
        Public repositories only — workers hold no git credentials. Scanning the
        same repository again adds to its history rather than creating a second
        project.
      </p>
    </div>
  );
}
