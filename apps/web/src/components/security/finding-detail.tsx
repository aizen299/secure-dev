"use client";

import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { XIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/api";
import { SeverityBadge } from "./severity";
import { FindingStatusBadge } from "./status";
import { RelativeTime } from "./relative-time";
import { Button } from "@/components/ui/button";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_minmax(0,1fr)] items-baseline gap-3 py-1.5">
      <dt className="eyebrow">{label}</dt>
      <dd className="min-w-0 text-[13px] text-ink">{children}</dd>
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="break-all font-mono text-[12px] text-ink-muted">{children}</span>;
}

/**
 * One finding, in a side panel.
 *
 * A panel rather than a separate route, because triage is a list activity: a
 * person reads a finding, decides, and moves to the next one. Navigating away
 * and back for each would lose the list position and the filter every time.
 */
export function FindingDetail({
  finding,
  onClose,
}: {
  finding: Finding | null;
  onClose: () => void;
}) {
  return (
    <Dialog.Root open={finding !== null} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50 data-[state=open]:animate-in data-[state=open]:fade-in-0" />
        <Dialog.Content
          className={cn(
            "fixed right-0 top-0 z-50 flex h-screen w-full max-w-xl flex-col",
            "border-l border-line bg-surface shadow-2xl shadow-black/50",
            "data-[state=open]:animate-in data-[state=open]:slide-in-from-right-4",
          )}
        >
          {finding && (
            <>
              <div className="flex items-start gap-3 border-b border-line px-5 py-4">
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <FindingStatusBadge status={finding.status} />
                    <span className="text-[11px] capitalize text-ink-faint">
                      {finding.category}
                    </span>
                  </div>
                  <Dialog.Title className="text-[15px] font-medium leading-snug tracking-tight text-ink">
                    {finding.title}
                  </Dialog.Title>
                </div>
                <Dialog.Close asChild>
                  <Button variant="ghost" size="icon-sm" aria-label="Close">
                    <XIcon />
                  </Button>
                </Dialog.Close>
              </div>

              <div className="flex-1 overflow-y-auto px-5 py-4">
                {finding.description && (
                  <p className="mb-4 text-[13px] leading-relaxed text-ink-muted">
                    {finding.description}
                  </p>
                )}

                <dl className="divide-y divide-line">
                  {finding.cve && <Field label="Identifier"><Mono>{finding.cve}</Mono></Field>}
                  {finding.cwe && <Field label="Weakness"><Mono>{finding.cwe}</Mono></Field>}
                  {finding.cvss !== undefined && finding.cvss > 0 && (
                    <Field label="CVSS">
                      <span className="tabular-nums">{finding.cvss.toFixed(1)}</span>
                    </Field>
                  )}
                  {finding.purl && <Field label="Component"><Mono>{finding.purl}</Mono></Field>}
                  {finding.package && !finding.purl && (
                    <Field label="Package">
                      <Mono>
                        {finding.package}
                        {finding.package_version ? `@${finding.package_version}` : ""}
                      </Mono>
                    </Field>
                  )}
                  {finding.image && <Field label="Image"><Mono>{finding.image}</Mono></Field>}
                  {finding.endpoint && <Field label="Endpoint"><Mono>{finding.endpoint}</Mono></Field>}

                  <Field label="Exploitation">
                    {finding.threat?.epss ? (
                      <span className="tabular-nums">
                        {(finding.threat.epss.probability * 100).toFixed(2)}%{" "}
                        <span className="text-ink-faint">
                          ({(finding.threat.epss.percentile * 100).toFixed(0)}th percentile,{" "}
                          {finding.threat.epss.source},{" "}
                          {finding.threat.epss.observed_at.slice(0, 10)})
                        </span>
                      </span>
                    ) : (
                      // Absence, stated. Not "0%" -- nobody measured this.
                      <span className="text-ink-faint">No signal available</span>
                    )}
                  </Field>

                  <Field label="Reported by">
                    <Mono>{(finding.sources ?? [finding.scanner]).join(", ")}</Mono>
                    {finding.sources && finding.sources.length > 1 && (
                      <span className="ml-2 text-[12px] text-ink-faint">
                        independent agreement
                      </span>
                    )}
                  </Field>

                  <Field label="Seen">
                    <span className="text-[12px] text-ink-muted">
                      first <RelativeTime value={finding.first_seen} />, last{" "}
                      <RelativeTime value={finding.last_seen} /> · {finding.occurrences}{" "}
                      {finding.occurrences === 1 ? "occurrence" : "occurrences"}
                    </span>
                  </Field>

                  <Field label="Fingerprint"><Mono>{finding.fingerprint}</Mono></Field>
                </dl>

                {finding.remediation && (
                  <div className="mt-5 rounded-lg border border-line bg-panel px-3.5 py-3">
                    <p className="mb-1.5 eyebrow">Remediation</p>
                    <p className="text-[13px] leading-relaxed text-ink-muted">
                      {finding.remediation}
                    </p>
                    {/* Provenance, always. §11 makes vendor data authoritative
                        and forbids presenting anything generated as verified,
                        so the source of this text is stated rather than
                        assumed. */}
                    <p className="mt-2 text-[11px] text-ink-faint">
                      From the scanner&apos;s own advisory data.
                    </p>
                  </div>
                )}
              </div>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
