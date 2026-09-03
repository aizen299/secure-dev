"use client";

import * as React from "react";
import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon, SearchIcon } from "lucide-react";
import type { Finding } from "@/lib/api";
import { SeverityBadge, SEVERITY_ORDER } from "./severity";
import { FindingStatusBadge } from "./status";
import { RelativeTime } from "./relative-time";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";

const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((s, i) => [s, i]));

type ColumnId =
  | "severity"
  | "title"
  | "category"
  | "scanner"
  | "status"
  | "epss"
  | "last_seen";

interface Column {
  id: ColumnId;
  header: string;
  width?: string;
  sortable?: boolean;
  cell: (finding: Finding) => React.ReactNode;
}

/** The value a column sorts on. Severity sorts by rank, never alphabetically:
 *  "critical" before "high" before "info" is the only order that means
 *  anything, and it is not the order the strings fall in. */
function sortValue(finding: Finding, column: ColumnId): number | string {
  switch (column) {
    case "severity":
      return SEVERITY_RANK.get(finding.severity) ?? 99;
    case "epss":
      // No signal sorts below every real probability rather than alongside
      // zero, because "nobody measured this" is not "unlikely" (ADR 018).
      return finding.threat?.epss?.probability ?? -1;
    case "last_seen":
      return Date.parse(finding.last_seen) || 0;
    case "title":
      return finding.title.toLowerCase();
    case "category":
      return finding.category;
    case "scanner":
      return finding.scanner;
    case "status":
      return finding.status;
  }
}

const HAYSTACK = (f: Finding) =>
  [f.title, f.purl, f.cve, f.cwe, f.package, f.endpoint, f.image, f.category, f.scanner]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

/**
 * The findings table.
 *
 * Sorting and filtering are implemented directly rather than through a table
 * library. What this needs is one comparator and one substring match over a
 * bounded list; a table library earns its place with virtualization, grouping,
 * or column visibility, none of which are used here, and it would add a
 * dependency whose major versions rename their own API.
 *
 * The server does the coarse filtering (status, severity) through the API,
 * because that decides which rows exist. This refines what is already on
 * screen, which is what makes it feel instant.
 */
export function FindingsTable({
  findings,
  onSelect,
  selectedId,
}: {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  selectedId?: string;
}) {
  const [sort, setSort] = React.useState<{ column: ColumnId; desc: boolean }>({
    column: "severity",
    desc: false,
  });
  const [filter, setFilter] = React.useState("");

  const columns = React.useMemo<Column[]>(
    () => [
      {
        id: "severity",
        header: "Severity",
        width: "110px",
        sortable: true,
        cell: (f) => <SeverityBadge severity={f.severity} />,
      },
      {
        id: "title",
        header: "Finding",
        sortable: true,
        cell: (f) => (
          <div className="min-w-0">
            <p className="truncate text-ink">{f.title}</p>
            <p className="truncate font-mono text-[11px] text-ink-faint">
              {f.purl ?? f.endpoint ?? f.image ?? f.category}
            </p>
          </div>
        ),
      },
      {
        id: "category",
        header: "Domain",
        width: "100px",
        sortable: true,
        cell: (f) => <span className="text-[12px] capitalize text-ink-muted">{f.category}</span>,
      },
      {
        // Provenance a person may want, never something the UI reasons about
        // (§7 rule 2, §25.3).
        id: "scanner",
        header: "Source",
        width: "120px",
        sortable: true,
        cell: (f) => (
          <span className="font-mono text-[11px] text-ink-faint">
            {(f.sources ?? [f.scanner]).join(", ")}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        width: "116px",
        sortable: true,
        cell: (f) => <FindingStatusBadge status={f.status} />,
      },
      {
        id: "epss",
        header: "EPSS",
        width: "84px",
        sortable: true,
        cell: (f) => {
          const epss = f.threat?.epss;
          // A dash, not a zero. No signal and a low probability are different
          // facts, and rendering both as 0% erases the distinction ADR 018
          // exists to keep.
          if (!epss) return <span className="text-[12px] text-ink-faint">—</span>;
          return (
            <span
              className="text-[12px] tabular-nums text-ink-muted"
              title={`${epss.source}, observed ${epss.observed_at.slice(0, 10)}`}
            >
              {(epss.probability * 100).toFixed(1)}%
            </span>
          );
        },
      },
      {
        id: "last_seen",
        header: "Last seen",
        width: "104px",
        sortable: true,
        cell: (f) => (
          <span className="text-[12px] text-ink-faint">
            <RelativeTime value={f.last_seen} />
          </span>
        ),
      },
    ],
    [],
  );

  const rows = React.useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const matched = needle ? findings.filter((f) => HAYSTACK(f).includes(needle)) : findings;

    return [...matched].sort((a, b) => {
      const left = sortValue(a, sort.column);
      const right = sortValue(b, sort.column);
      const order = left < right ? -1 : left > right ? 1 : 0;
      return sort.desc ? -order : order;
    });
  }, [findings, filter, sort]);

  const toggle = (column: ColumnId) =>
    setSort((current) =>
      current.column === column
        ? { column, desc: !current.desc }
        : { column, desc: column !== "severity" && column !== "title" },
    );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="relative max-w-xs flex-1">
          <SearchIcon className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-ink-faint" />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by title, package, CVE…"
            className="pl-7"
            aria-label="Filter findings"
          />
        </div>
        <span className="text-[12px] tabular-nums text-ink-faint">
          {rows.length === findings.length
            ? `${findings.length} shown`
            : `${rows.length} of ${findings.length}`}
        </span>
      </div>

      <div className="overflow-hidden rounded-lg border border-line bg-panel">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              {columns.map((column) => (
                <TableHead key={column.id} style={{ width: column.width }}>
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => toggle(column.id)}
                      aria-label={`Sort by ${column.header}`}
                      className="inline-flex items-center gap-1 uppercase tracking-[0.06em] hover:text-ink-muted"
                    >
                      {column.header}
                      {sort.column !== column.id ? (
                        <ChevronsUpDownIcon className="size-3 opacity-40" />
                      ) : sort.desc ? (
                        <ArrowDownIcon className="size-3" />
                      ) : (
                        <ArrowUpIcon className="size-3" />
                      )}
                    </button>
                  ) : (
                    column.header
                  )}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>

          <TableBody>
            {rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center text-[13px] text-ink-faint"
                >
                  Nothing matches that filter.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((finding) => (
                <TableRow
                  key={finding.id}
                  tabIndex={0}
                  role="button"
                  data-state={finding.id === selectedId ? "selected" : undefined}
                  onClick={() => onSelect(finding)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(finding);
                    }
                  }}
                  className="cursor-pointer"
                >
                  {columns.map((column) => (
                    <TableCell key={column.id} className="max-w-0">
                      {column.cell(finding)}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
