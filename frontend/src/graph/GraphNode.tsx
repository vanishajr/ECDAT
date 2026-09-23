// Crypto graph node: compact card with type bar, severity pill, and
// aggregate count. Keyboard-operable (tabIndex + Enter/Space) with the
// same selection path as mouse clicks. Never invents content: every
// line comes from node data with tooltip + aria fallbacks.

import { Handle, Position, useStore } from "@xyflow/react";
import type { NodeProps } from "@xyflow/react";
import { Layers } from "lucide-react";

export interface CryptoNodeData {
  title: string;
  fullTitle: string;
  subtitle: string;
  risk: string;
  /** Muted per-type accent (inner bar); risk keeps the pill. */
  tone?: string;
  /** Tinted severity pill (label + classes); null hides it. */
  pill?: { label: string; className: string } | null;
  /** Member count for aggregate nodes; omit or 1 for singles. */
  count?: number;
  /** True when the node links to a finding (marker + aria note). */
  finding?: boolean;
  /** Render footprint; layout reserves the identical box (no overlap). */
  width?: number;
  height?: number;
  /** Primary entities render larger type; supporting context compact. */
  primary?: boolean;
  /** Keyboard/mouse activation; wired by CryptoGraph to selection. */
  onSelect?: (id: string) => void;
  [key: string]: unknown;
}

// Risk dot palette mirrors the dashboard `dotTone` scale in App.tsx so
// graph risk reads identically to findings/severity elsewhere.
const DOT_TONE: Record<string, string> = {
  critical: "bg-[#b8424d]",
  high: "bg-[#a96f52]",
  medium: "bg-[#d78b3e]",
  low: "bg-[#b88945]",
  info: "bg-[#6586a4]",
};

function dotTone(level: unknown): string {
  return DOT_TONE[String(level ?? "info").toLowerCase()] ?? DOT_TONE.info;
}

const ZOOM_DETAIL = 0.55;

export function GraphNode({ data, selected, id }: NodeProps) {
  const zoom = useStore((s) => s.transform[2]);
  const d = data as unknown as CryptoNodeData;
  const showDetail = zoom >= ZOOM_DETAIL;
  const count = typeof d.count === "number" && d.count > 1 ? d.count : 0;
  const finding = d.finding === true;
  const primary = d.primary !== false;
  const width = typeof d.width === "number" && d.width > 0 ? d.width : 240;
  const minHeight = typeof d.height === "number" && d.height > 0 ? d.height : undefined;
  const pill = d.pill && typeof d.pill === "object" ? d.pill : null;
  const activate = () => d.onSelect?.(id);
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`${d.fullTitle || d.title} (${d.subtitle || "graph node"}, risk ${d.risk || "info"}${count ? `, ${count} occurrences` : ""}${finding ? ", linked to findings" : ""}). Press Enter to inspect.`}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          activate();
        }
      }}
      onClick={activate}
      className={`relative flex flex-col justify-center rounded-xl border bg-[#f8f6f1] py-2 pl-3 pr-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#181a19] ${
        selected
          ? "border-[#181a19] shadow-[0_6px_18px_rgba(24,26,25,.18)] ring-1 ring-[#181a19]"
          : "border-[#d4d0c8] shadow-sm"
      }`}
      style={{ width, minHeight }}
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute bottom-2 left-0 top-2 w-1 rounded-full"
        style={{ background: typeof d.tone === "string" && d.tone ? d.tone : "transparent" }}
      />
      <Handle type="target" position={Position.Top} style={{ opacity: 0, width: 1, height: 1 }} />
      <div className="flex items-center gap-1.5">
        <i
          className={`h-2 w-2 shrink-0 rounded-full ${dotTone(d.risk)}${finding ? " ring-1 ring-[#181a19] ring-offset-1 ring-offset-[#f8f6f1]" : ""}`}
          aria-hidden="true"
        />
        <b
          className={`${primary ? "text-[13px]" : "text-xs"} min-w-0 flex-1 truncate font-semibold`}
          title={d.fullTitle || d.title}
        >
          {d.title}
        </b>
        {pill && (
          <span
            className={`shrink-0 rounded px-1 py-px text-[9px] font-bold tracking-wide ${pill.className}`}
          >
            {pill.label}
          </span>
        )}
        {count > 0 && (
          <span
            className="flex shrink-0 items-center gap-0.5 rounded-full bg-[#e8e4dc] px-1.5 py-0.5 text-[10px] font-semibold text-[#292a28]"
            title={`${count} occurrences — click to list members`}
          >
            <Layers size={10} aria-hidden="true" />
            {count}
          </span>
        )}
      </div>
      {showDetail && d.subtitle ? (
        <span className="mt-0.5 block truncate text-[10px] text-[#6b675f]">
          {d.subtitle}
        </span>
      ) : null}
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0, width: 1, height: 1 }} />
    </div>
  );
}
