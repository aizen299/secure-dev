import Link from "next/link";
import { ScanLineIcon } from "lucide-react";
import { listProjectScans, optional } from "@/lib/api";
import { PageBody } from "@/components/shell/page-header";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/security/empty";
import { ScanStatusBadge } from "@/components/security/status";
import { RelativeTime } from "@/components/security/relative-time";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export const dynamic = "force-dynamic";

function targetOf(scan: { target: { kind: string; repository_url?: string; image?: string; endpoint_url?: string } }) {
  return (
    scan.target.repository_url ?? scan.target.image ?? scan.target.endpoint_url ?? scan.target.kind
  );
}

export default async function ScansPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const scans = await optional(() => listProjectScans(projectId, { limit: 50 }));

  if (!scans || scans.data.length === 0) {
    return (
      <PageBody>
        <Card>
          <EmptyState
            icon={<ScanLineIcon className="size-4" />}
            title="No scans"
            description="Nothing has been submitted for this project yet."
          />
        </Card>
      </PageBody>
    );
  }

  return (
    <PageBody>
      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead style={{ width: "110px" }}>Status</TableHead>
              <TableHead>Target</TableHead>
              <TableHead style={{ width: "140px" }}>Commit</TableHead>
              <TableHead style={{ width: "120px" }}>Coverage</TableHead>
              <TableHead style={{ width: "100px" }}>Queued</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.data.map((scan) => (
              <TableRow key={scan.id} className="cursor-pointer">
                <TableCell>
                  <Link href={`/projects/${projectId}/scans/${scan.id}`} className="block">
                    <ScanStatusBadge status={scan.status} />
                  </Link>
                </TableCell>
                <TableCell className="max-w-0">
                  <Link href={`/projects/${projectId}/scans/${scan.id}`} className="block">
                    <p className="truncate font-mono text-[12px] text-ink-muted">
                      {targetOf(scan)}
                    </p>
                  </Link>
                </TableCell>
                <TableCell>
                  <Link href={`/projects/${projectId}/scans/${scan.id}`} className="block">
                    <span className="font-mono text-[11px] text-ink-faint">
                      {scan.commit_sha ? scan.commit_sha.slice(0, 10) : "—"}
                    </span>
                  </Link>
                </TableCell>
                <TableCell>
                  <Link href={`/projects/${projectId}/scans/${scan.id}`} className="block">
                    {scan.complete_coverage ? (
                      <span className="text-[12px] text-ink-faint">Complete</span>
                    ) : (
                      // Never silent. §13 turns on a partial scan not reading
                      // as a successful one.
                      <span className="text-[12px] text-warn">Degraded</span>
                    )}
                  </Link>
                </TableCell>
                <TableCell>
                  <Link href={`/projects/${projectId}/scans/${scan.id}`} className="block">
                    <span className="text-[12px] text-ink-faint">
                      <RelativeTime value={scan.queued_at} />
                    </span>
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </PageBody>
  );
}
