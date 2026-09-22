// Edge presentation helpers (pure): what label/style an edge gets and
// when. Labels are hidden by default and revealed on hover/selection;
// low-priority edges render subtly. Source/target/id/type semantics
// are never altered here — only display properties.

import type { GraphEdgeDatum } from "./graphTypes";

export interface EdgeDisplay {
  /** Hover/selection label; undefined keeps the edge unlabeled. */
  label: string | undefined;
  /** True for background relationships (plain `uses` without detail). */
  lowPriority: boolean;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Full relationship text for hover/selection display (no truncation:
 *  revealed labels are rare by design, so completeness beats brevity). */
export function edgeLabel(edge: GraphEdgeDatum): string {
  return [str(edge.type), str(edge.detail)]
    .filter(Boolean)
    .join(" · ")
    .trim()
    .replace(/\s+/g, " ");
}

export function isLowPriority(edge: GraphEdgeDatum): boolean {
  return str(edge.type) === "uses" && str(edge.detail) === "";
}

export function edgeDisplay(
  edge: GraphEdgeDatum,
  active: boolean,
): EdgeDisplay {
  if (!edge || typeof edge !== "object") return { label: undefined, lowPriority: false };
  return {
    label: active ? edgeLabel(edge) || undefined : undefined,
    lowPriority: isLowPriority(edge),
  };
}

export const EDGE_STYLE = {
  base: { stroke: "#8f887c", strokeWidth: 1.5 },
  low: { stroke: "#b3aca0", strokeWidth: 1 },
  hover: { stroke: "#5e5d58", strokeWidth: 2 },
  active: { stroke: "#181a19", strokeWidth: 2.5 },
} as const;
