import { KeyRoundIcon } from "lucide-react";
import { Card } from "@/components/ui/card";

/**
 * Shown when the dashboard has no credential.
 *
 * A deployment problem, not a data problem, and it says so. Rendering an empty
 * project list here would be the worst outcome available: an operator would
 * read "no projects" and conclude the platform is empty when in fact it is
 * unreachable (§13's distinction, applied to the UI).
 */
export function SetupNotice() {
  return (
    <Card className="mx-auto max-w-xl">
      <div className="flex flex-col items-center gap-3 px-6 py-10 text-center">
        <div className="flex size-9 items-center justify-center rounded-lg border border-warn/25 bg-warn-dim text-warn">
          <KeyRoundIcon className="size-4" />
        </div>
        <p className="text-[13px] font-medium text-ink">The dashboard has no API credential</p>
        <p className="max-w-md text-[12px] leading-relaxed text-ink-faint">
          This is a configuration gap, not an empty platform — there may well be
          projects and findings the dashboard cannot currently read.
        </p>
        <div className="mt-1 w-full rounded-md border border-line bg-surface px-3 py-2.5 text-left">
          <p className="mb-1.5 eyebrow">Set on the web service</p>
          <code className="block font-mono text-[12px] leading-relaxed text-ink-muted">
            SECUREOPS_API_TOKEN=&lt;secret&gt;
          </code>
        </div>
        <p className="max-w-md text-[11px] leading-relaxed text-ink-faint">
          This is the <em>secret</em> alone — the third field of a{" "}
          <span className="font-mono">label:role:secret</span> entry in the API&apos;s{" "}
          <span className="font-mono">SECUREOPS_API_TOKENS</span>, not the whole triple.
          Use a <span className="font-mono">viewer</span> role: the dashboard only reads,
          and a stronger one would let a page act with authority nobody signed in for.
        </p>
      </div>
    </Card>
  );
}
