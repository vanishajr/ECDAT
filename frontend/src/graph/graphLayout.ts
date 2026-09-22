// Automatic graph layout via ELK.js (layered, top-down).
// Deterministic: inputs are sorted by id before layout, so the same
// graph always yields the same positions. Any ELK failure (or an
// empty/malformed input) falls back to a deterministic index grid —
// the graph always renders.

import ELK from "elkjs/lib/elk.bundled.js";
import { connectedComponents } from "./graphComponents";

// Width reserved per node in ELK. Must cover the rendered GraphNode
// max-width (230px) plus a margin — a smaller value lets neighbors in
// dense layers overlap by a few pixels.
export const LAYOUT_NODE_WIDTH = 240;
export const LAYOUT_NODE_HEIGHT = 72;

export interface LayoutInputNode {
  id: string;
  /** Per-node footprint; defaults keep single-size callers working. */
  width?: number;
  height?: number;
}

export interface LayoutInputEdge {
  source: string;
  target: string;
}

export interface LayoutPosition {
  id: string;
  x: number;
  y: number;
}

interface ElkLike {
  layout: (graph: unknown) => Promise<{
    children?: Array<{ id: string; x?: number; y?: number }>;
  }>;
}

const ELK_OPTIONS: Record<string, string> = {
  "elk.algorithm": "layered",
  "elk.direction": "DOWN",
  // Compact but non-overlapping for 200px-class cards: measured on the
  // live 210-node scan (see packing tests) to shrink the packed block
  // ~30% versus the previous 48/96 without node overlap.
  "elk.spacing.nodeNode": "36",
  "elk.layered.spacing.nodeNodeBetweenLayers": "80",
  // No elk.edgeRouting: React Flow draws the edges (smoothstep), ELK only
  // positions nodes — requesting edge routes would waste layout time.
  "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
  // NETWORK_SIMPLEX compacts long layers: measured 2984x2124 -> 2820x1358
  // on the live 210-node scan versus the default SIMPLE placement.
  "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
};

let sharedElk: ElkLike | null = null;

function elk(): ElkLike {
  if (!sharedElk) sharedElk = new ELK() as unknown as ElkLike;
  return sharedElk;
}

/** Deterministic fallback: index-ordered grid, no type columns. */
export function fallbackLayout(ids: string[]): LayoutPosition[] {  const sorted = [...ids].sort();
  const perRow = Math.max(1, Math.ceil(Math.sqrt(sorted.length)));
  return sorted.map((id, i) => ({
    id,
    x: (i % perRow) * (LAYOUT_NODE_WIDTH + 80) + 20,
    y: Math.floor(i / perRow) * (LAYOUT_NODE_HEIGHT + 80) + 20,
  }));
}

export const PACK_PAD = 48;
// Row width tuned for the graph card (~700px wide at 1.6fr): narrower
// rows stack components into a compact block that fills the card instead
// of one wide, short, zoomed-out shelf.
export const PACK_ROW_WIDTH = 1100;

export interface ContentBounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  width: number;
  height: number;
  centerX: number;
  centerY: number;
}

/**
 * Measured bounds of laid-out positions including node extents.
 * Used to verify packing compactness; empty input yields a zero box.
 */
export function contentBounds(
  positions: LayoutPosition[],
  nodeWidth: number = LAYOUT_NODE_WIDTH,
  nodeHeight: number = LAYOUT_NODE_HEIGHT,
): ContentBounds {
  if (!positions || positions.length === 0) {
    return { minX: 0, minY: 0, maxX: 0, maxY: 0, width: 0, height: 0, centerX: 0, centerY: 0 };
  }
  const xs = positions.map((p) => p.x);
  const ys = positions.map((p) => p.y);
  const minX = Math.min(...xs);
  const minY = Math.min(...ys);
  const maxX = Math.max(...xs) + nodeWidth;
  const maxY = Math.max(...ys) + nodeHeight;
  return {
    minX, minY, maxX, maxY,
    width: maxX - minX,
    height: maxY - minY,
    centerX: (minX + maxX) / 2,
    centerY: (minY + maxY) / 2,
  };
}

/**
 * Component-packed layout: each connected component is laid out on its
 * own (isolated nodes skip ELK via a fast path), then components are
 * shelf-packed into compact rows. Removes the oceans of empty space a
 * single global layout leaves around small/disconnected subgraphs.
 * Deterministic for identical inputs; never mutates inputs.
 */
export async function layoutPacked(
  nodes: LayoutInputNode[],
  edges: LayoutInputEdge[],
  elkImpl: ElkLike | null = null,
): Promise<LayoutPosition[]> {
  const ids = (nodes ?? [])
    .filter((n) => n && typeof n.id === "string" && n.id !== "")
    .map((n) => String(n.id));
  const unique = [...new Set(ids)];
  if (unique.length === 0) return [];
  const idSet = new Set(unique);
  const cleanEdges = (edges ?? [])
    .filter(
      (e) =>
        e &&
        typeof e.source === "string" &&
        typeof e.target === "string" &&
        idSet.has(String(e.source)) &&
        idSet.has(String(e.target)),
    )
    .map((e) => ({ source: String(e.source), target: String(e.target) }));

  const components = connectedComponents(unique, cleanEdges);
  const sizeOf = (id: string): { width: number; height: number } => {
    const found = (nodes ?? []).find(
      (n) => n && typeof n.id === "string" && String(n.id) === id,
    );
    return {
      width: Number(found?.width) || LAYOUT_NODE_WIDTH,
      height: Number(found?.height) || LAYOUT_NODE_HEIGHT,
    };
  };
  const byKey = new Map<string, LayoutPosition[]>();
  await Promise.all(
    components.map(async (c) => {
      if (c.isolated) {
        byKey.set(c.root, [{ id: c.root, x: 0, y: 0 }]);
        return;
      }
      const internal = cleanEdges.filter(
        (e) => c.members.includes(e.source) && c.members.includes(e.target),
      );
      const laid = await layoutGraph(
        c.members.map((id) => ({ id, ...sizeOf(id) })),
        internal,
        elkImpl,
      );
      byKey.set(c.root, laid);
    }),
  );

  // Shelf-pack component bounding boxes into compact rows.
  const boxes = components.map((c) => {
    const laid = byKey.get(c.root) ?? [{ id: c.root, x: 0, y: 0 }];
    const minX = Math.min(...laid.map((p) => p.x));
    const minY = Math.min(...laid.map((p) => p.y));
    const maxX = Math.max(
      ...laid.map((p) => p.x + sizeOf(p.id).width),
    );
    const maxY = Math.max(
      ...laid.map((p) => p.y + sizeOf(p.id).height),
    );
    return {
      laid,
      w: maxX - minX,
      h: maxY - minY,
      minX,
      minY,
    };
  });
  const out: LayoutPosition[] = [];
  let cursorX = 0;
  let cursorY = 0;
  let rowH = 0;
  for (const box of boxes) {
    if (cursorX > 0 && cursorX + box.w > PACK_ROW_WIDTH) {
      cursorX = 0;
      cursorY += rowH + PACK_PAD;
      rowH = 0;
    }
    for (const p of box.laid) {
      out.push({ id: p.id, x: p.x - box.minX + cursorX, y: p.y - box.minY + cursorY });
    }
    cursorX += box.w + PACK_PAD;
    rowH = Math.max(rowH, box.h);
  }
  // Normalize origin so the graph starts near (20, 20).
  const ox = Math.min(...out.map((p) => p.x));
  const oy = Math.min(...out.map((p) => p.y));
  return out
    .map((p) => ({ id: p.id, x: Math.round(p.x - ox + 20), y: Math.round(p.y - oy + 20) }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

export async function layoutGraph(
  nodes: LayoutInputNode[],
  edges: LayoutInputEdge[],
  elkImpl: ElkLike | null = null,
): Promise<LayoutPosition[]> {
  const ids = (nodes ?? [])
    .filter((n) => n && typeof n.id === "string" && n.id !== "")
    .map((n) => String(n.id));
  const unique = [...new Set(ids)].sort();
  if (unique.length === 0) return [];

  const idSet = new Set(unique);
  const cleanEdges = (edges ?? []).filter(
    (e) =>
      e &&
      typeof e.source === "string" &&
      typeof e.target === "string" &&
      idSet.has(String(e.source)) &&
      idSet.has(String(e.target)),
  );

  try {
    const engine = elkImpl ?? elk();
    const sized = new Map(
      unique.map((id) => {
        const found = (nodes ?? []).find(
          (n) => n && typeof n.id === "string" && String(n.id) === id,
        );
        return [id, found] as const;
      }),
    );
    const result = await engine.layout({
      id: "root",
      layoutOptions: ELK_OPTIONS,
      children: unique.map((id) => ({
        id,
        width: Number(sized.get(id)?.width) || LAYOUT_NODE_WIDTH,
        height: Number(sized.get(id)?.height) || LAYOUT_NODE_HEIGHT,
      })),
      edges: cleanEdges.map((e, i) => ({
        id: `e${i}`,
        sources: [String(e.source)],
        targets: [String(e.target)],
      })),
    });
    const positions = new Map<string, LayoutPosition>();
    for (const child of result.children ?? []) {
      if (child && typeof child.id === "string" && idSet.has(child.id)) {
        positions.set(child.id, {
          id: child.id,
          x: Math.round(child.x ?? 0),
          y: Math.round(child.y ?? 0),
        });
      }
    }
    // ELK must position every node; otherwise the fallback keeps it honest.
    if (positions.size !== unique.length) return fallbackLayout(unique);
    return unique.map((id) => positions.get(id) as LayoutPosition);
  } catch {
    return fallbackLayout(unique);
  }
}
