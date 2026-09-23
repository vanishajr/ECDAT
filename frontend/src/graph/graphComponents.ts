// Connected-component detection (union-find, undirected) for compact
// component packing. Pure logic — layout lives in graphLayout.ts.

export interface ComponentEdge {
  source: string;
  target: string;
}

export interface ComponentInfo {
  /** Deterministic root id (lexicographically smallest member). */
  root: string;
  /** Sorted member ids. */
  members: string[];
  /** True for single nodes with no edges to other nodes. */
  isolated: boolean;
}

export function connectedComponents(
  nodeIds: string[],
  edges: ComponentEdge[],
): ComponentInfo[] {
  const ids = [...new Set(
    (nodeIds ?? [])
      .filter((id) => typeof id === "string" && id !== "")
      .map(String),
  )];
  const parent = new Map<string, string>(ids.map((id) => [id, id]));
  const find = (x: string): string => {
    let root = x;
    while (parent.get(root) !== root) root = parent.get(root) as string;
    // Path compression.
    let cur = x;
    while (parent.get(cur) !== root) {
      const next = parent.get(cur) as string;
      parent.set(cur, root);
      cur = next;
    }
    return root;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra < rb ? rb : ra, ra < rb ? ra : rb);
  };

  const linked = new Set<string>();
  for (const e of edges ?? []) {
    if (!e || typeof e !== "object") continue;
    const src = String(e.source ?? "");
    const dst = String(e.target ?? "");
    if (!parent.has(src) || !parent.has(dst)) continue;
    if (src === dst) {
      linked.add(src);
      continue;
    }
    linked.add(src);
    linked.add(dst);
    union(src, dst);
  }

  const groups = new Map<string, string[]>();
  for (const id of ids) {
    const root = find(id);
    const group = groups.get(root);
    if (group) group.push(id);
    else groups.set(root, [id]);
  }
  return [...groups.values()]
    .map((members) => {
      const sorted = [...members].sort();
      return {
        root: sorted[0],
        members: sorted,
        isolated: sorted.length === 1 && !linked.has(sorted[0]),
      };
    })
    .sort(
      (a, b) =>
        b.members.length - a.members.length ||
        (a.root < b.root ? -1 : a.root > b.root ? 1 : 0),
    );
}
