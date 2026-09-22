// Graph view modes (pure logic): which subset of the already-filtered
// graph each mode displays. Never mutates inputs; counts always describe
// how much is hidden so the UI can offer a way back.

import { neighborhood } from "./graphFocus";

export type GraphViewMode = "explore" | "neighborhood";

/**
 * Search + type filtering shared by all views (pure). Matches label,
 * id, and type case-insensitively; "All" disables the type gate.
 */
export function filterGraphNodes<T extends { id?: unknown; label?: unknown; type?: unknown }>(
  nodes: T[],
  query: string,
  typeFilter: string,
): T[] {
  const q = query.trim().toLowerCase();
  return (Array.isArray(nodes) ? nodes : []).filter(
    (n) =>
      n != null &&
      typeof n === "object" &&
      (typeFilter === "All" || (n as { type?: unknown }).type === typeFilter) &&
      (!q ||
        `${(n as { label?: unknown }).label || ""} ${(n as { id?: unknown }).id || ""} ${(n as { type?: unknown }).type || ""}`
          .toLowerCase()
          .includes(q)),
  );
}

export interface ViewSlice {
  /** Ids to render in this view. */
  nodeIds: Set<string>;
  /** Edge ids to render in this view. */
  edgeIds: Set<string>;
  /** Visible nodes withheld by this view (recoverable via Explore). */
  hiddenNodes: number;
  /** Visible edges withheld by this view. */
  hiddenEdges: number;
}

interface SliceEdge {
  id: string;
  source: string;
  target: string;
}

/**
 * `visibleIds`/`visibleEdges` are the search/type/cap-filtered graph
 * (edge ids must match the ids used for rendering).
 * Explore returns them untouched; neighborhood returns the selected
 * node's 1-hop scope (or an empty slice when nothing is selected).
 */
export function sliceForView(
  visibleIds: Set<string> | string[],
  visibleEdges: SliceEdge[],
  mode: GraphViewMode,
  selectedId: string | null,
): ViewSlice {
  const visible = new Set(
    [...visibleIds].map((id) => String(id)),
  );
  const edges = (Array.isArray(visibleEdges) ? visibleEdges : []).filter(
    (e) =>
      e &&
      typeof e === "object" &&
      typeof e.id === "string" &&
      visible.has(String(e.source)) &&
      visible.has(String(e.target)),
  );
  const byId = new Map(edges.map((e) => [String(e.id), e]));
  if (mode !== "neighborhood" || selectedId == null) {
    return { nodeIds: visible, edgeIds: new Set(byId.keys()), hiddenNodes: 0, hiddenEdges: 0 };
  }
  const focus = neighborhood(
    selectedId,
    edges.map((e) => ({
      id: String(e.id),
      source: String(e.source),
      target: String(e.target),
      type: "",
    })),
  );
  const nodeIds = new Set([...focus.keep].filter((id) => visible.has(id)));
  const edgeIds = new Set(
    [...focus.edgeKeep].filter((id) => byId.has(id)),
  );
  return {
    nodeIds,
    edgeIds,
    hiddenNodes: visible.size - nodeIds.size,
    hiddenEdges: byId.size - edgeIds.size,
  };
}
