"use client";

import * as React from "react";
import type { Finding } from "@/lib/api";
import { FindingsTable } from "./findings-table";
import { FindingDetail } from "./finding-detail";

/** Holds the selection that the table and the detail panel share. */
export function FindingsBrowser({ findings }: { findings: Finding[] }) {
  const [selected, setSelected] = React.useState<Finding | null>(null);

  return (
    <>
      <FindingsTable findings={findings} onSelect={setSelected} selectedId={selected?.id} />
      <FindingDetail finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}
