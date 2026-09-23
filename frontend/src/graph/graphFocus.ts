// 1-hop neighborhood computation for graph focus mode (pure logic).
// Malformed edges are skipped; nothing here touches the DOM or React Flow.

import type { GraphEdgeDatum } from "./graphTypes";

export interface Neighborhood {
  /** Node ids to keep fully visible (selected + direct neighbors). */
  keep: Set<string>;
  /** Edge ids touching the selected node. */
  edgeKeep: Set<string>;
}

function edgeId(e: GraphEdgeDatum): string {
  return String(e.id ?? `${e.source}|${e.target}`);
}

/**
 * Nodes/edges to emphasize when `selectedId` is focused.
 * `null` selection means "no focus" — the caller keeps the full graph.
 */
export function neighborhood(
  selectedId: string | null,
  edges: GraphEdgeDatum[],
): Neighborhood {
  const keep = new Set<string>();
  const edgeKeep = new Set<string>();
  if (selectedId == null) return { keep, edgeKeep };
  const sel = String(selectedId);
  keep.add(sel);
  for (const e of edges) {
    if (!e || typeof e !== "object") continue;
    const src = e.source == null ? "" : String(e.source);
    const dst = e.target == null ? "" : String(e.target);
    if (!src || !dst) continue;
    if (src === sel) {
      keep.add(dst);
      edgeKeep.add(edgeId(e));
    } else if (dst === sel) {
      keep.add(src);
      edgeKeep.add(edgeId(e));
    }
  }
  return { keep, edgeKeep };
}
