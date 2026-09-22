// Security Map derivation: raw contract graph -> bounded,
// finding-oriented, connected derived graph. Pure, deterministic,
// immutable (never mutates inputs). Aggregates retain memberIds;
// rewired edges retain counts and never merge relationship types.

import { riskRankOf } from "./graphTypes";
import type { GraphEdgeDatum, GraphNodeDatum } from "./graphTypes";
import { describeNode } from "./graphLabels";
import { typeTone } from "./graphModel";

export const SECURITY_MAP_BUDGET = 8;
export const SECURITY_MAP_NODE_CAP = 26;

/** Render dimensions: primary entities read first, context stays compact.
 * Layout MUST use these same values (passed per node to ELK). */
export const NODE_SIZE_PRIMARY = { width: 240, height: 78 };
export const NODE_SIZE_SUPPORTING = { width: 208, height: 64 };

/** Primary = specific finding linkage + meaningful risk. */
export function isPrimary(risk: string, finding: boolean): boolean {
  return finding && (risk === "critical" || risk === "high" || risk === "medium");
}

/** Rule IDs too generic to signal a real finding. */
export const GENERIC_RULE_IDS = new Set(["", "-", "CRYPTOGRAPHY"]);

/** Seed preference for equal risk/degree: operations and assets first. */
const TYPE_SEED_WEIGHT: Record<string, number> = {
  CryptoOperation: 0,
  CryptoAsset: 1,
  CertificateKey: 2,
  Service: 3,
  Library: 4,
  Endpoint: 5,
};

export function typeSeedWeight(type: unknown): number {
  return TYPE_SEED_WEIGHT[String(type ?? "")] ?? 6;
}

/** True finding linkage: a specific rule, not a generic bucket. */
export function isFindingLinked(node: GraphNodeDatum): boolean {
  const rule = str(node.rule_id);
  return rule !== "" && !GENERIC_RULE_IDS.has(rule);
}

export interface SecurityMapNode {
  id: string;
  kind: "single" | "aggregate";
  /** Original node type (aggregates: shared member type). */
  type: string;
  title: string;
  subtitle: string;
  fullTitle: string;
  risk: string;
  tone: string;
  count: number;
  memberIds: string[];
  /** Stable aggregation key, present on aggregates only. */
  aggKey?: string;
  /** True when any member links to a finding (has rule_id). */
  finding: boolean;
  /** Primary entities render larger; supporting context stays compact. */
  primary: boolean;
}

export interface SecurityMapEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  count: number;
  /** Original edge id when count is 1. */
  sourceEdgeId?: string;
}

export interface SecurityMap {
  nodes: SecurityMapNode[];
  edges: SecurityMapEdge[];
  /** Elements considered before bounding (singles + aggregates). */
  totalElements: number;
  /** Elements withheld by the budget (recoverable in Explore). */
  hiddenElements: number;
  /** Raw nodes not represented in the map. */
  hiddenNodes: number;
  strategy: string;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function meta(n: GraphNodeDatum): Record<string, unknown> {
  return n.metadata && typeof n.metadata === "object"
    ? (n.metadata as Record<string, unknown>)
    : {};
}

/** Reliable identity for library repetition: same label + library. */
export function libraryKey(n: GraphNodeDatum): string | null {
  if (str(n.type) !== "Library") return null;
  const m = meta(n);
  return `Library|${str(n.label)}|${str(m.library)}`;
}

/** Reliable identity for algorithm repetition: same spec. */
export function assetKey(n: GraphNodeDatum): string | null {
  if (str(n.type) !== "CryptoAsset") return null;
  const m = meta(n);
  const num = (v: unknown) =>
    typeof v === "number" && Number.isFinite(v) ? String(v) : "";
  return `Asset|${str(m.canonical)}|${num(m.key_size)}|${str(m.mode)}|${str(m.curve)}|${str(m.protocol)}`;
}

interface Element {
  id: string;
  kind: "single" | "aggregate";
  type: string;
  risk: string;
  degree: number;
  label: string;
  memberIds: string[];
  aggKey?: string;
  finding: boolean;
}

function rankOf(risk: string): number {
  return riskRankOf(risk);
}

function compareElements(a: Element, b: Element): number {
  return (
    rankOf(a.risk) - rankOf(b.risk) ||
    Number(b.finding) - Number(a.finding) ||
    b.degree - a.degree ||
    typeSeedWeight(a.type) - typeSeedWeight(b.type) ||
    a.label.localeCompare(b.label) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  );
}

export function buildSecurityMap(
  rawNodes: GraphNodeDatum[],
  rawEdges: GraphEdgeDatum[],
  opts: { budget?: number; nodeCap?: number } = {},
): SecurityMap {
  const budget = opts.budget ?? SECURITY_MAP_BUDGET;
  const nodeCap = opts.nodeCap ?? SECURITY_MAP_NODE_CAP;
  const nodes = (Array.isArray(rawNodes) ? rawNodes : []).filter(
    (n) => n && typeof n === "object" && n.id != null && String(n.id) !== "",
  );
  const byId = new Map(nodes.map((n) => [String(n.id), n]));
  const cleanEdges = (Array.isArray(rawEdges) ? rawEdges : []).filter(
    (e) =>
      e &&
      typeof e === "object" &&
      byId.has(String(e.source)) &&
      byId.has(String(e.target)),
  );

  // 1. Aggregate repetition with >= 2 members; singletons stay individual.
  const groups = new Map<string, GraphNodeDatum[]>();
  const keyOf = new Map<string, string>();
  for (const n of nodes) {
    const key = libraryKey(n) ?? assetKey(n);
    if (!key) continue;
    keyOf.set(String(n.id), key);
    const g = groups.get(key);
    if (g) g.push(n);
    else groups.set(key, [n]);
  }
  const aggIdOf = new Map<string, string>();
  for (const [key, members] of groups) {
    if (members.length < 2) {
      keyOf.delete(String(members[0].id));
      continue;
    }
    const aggId = `map:${key}`;
    for (const m of members) aggIdOf.set(String(m.id), aggId);
  }
  const repOf = (id: string): string => aggIdOf.get(id) ?? id;

  // 2. Representative-level adjacency (distinct neighbors only).
  const neighbors = new Map<string, Set<string>>();
  const touch = (a: string, b: string) => {
    if (a === b) return;
    if (!neighbors.has(a)) neighbors.set(a, new Set());
    if (!neighbors.has(b)) neighbors.set(b, new Set());
    neighbors.get(a)!.add(b);
    neighbors.get(b)!.add(a);
  };
  for (const e of cleanEdges) touch(repOf(String(e.source)), repOf(String(e.target)));

  // 3. Elements: singles + multi-member aggregates.
  const elements = new Map<string, Element>();
  const aggMembers = new Map<string, GraphNodeDatum[]>();
  for (const [id, n] of byId) {
    const aggId = aggIdOf.get(id);
    if (!aggId) {
      const label = describeNode(n);
      elements.set(id, {
        id,
        kind: "single",
        type: str(n.type),
        risk: str(n.risk) || "info",
        degree: neighbors.get(id)?.size ?? 0,
        label: label.title,
        memberIds: [id],
        finding: isFindingLinked(n as GraphNodeDatum),
      });
    } else {
      const g = aggMembers.get(aggId);
      if (g) g.push(n);
      else aggMembers.set(aggId, [n]);
    }
  }
  for (const [aggId, members] of aggMembers) {
    const first = members[0];
    const worst = members.reduce(
      (w, m) => (rankOf(str(m.risk) || "info") < rankOf(w) ? str(m.risk) || "info" : w),
      str(first.risk) || "info",
    );
    const label = describeNode(first);
    const key = [...groups.keys()].find((k) => `map:${k}` === aggId) ?? aggId;
    elements.set(aggId, {
      id: aggId,
      kind: "aggregate",
      type: str(first.type),
      risk: worst,
      degree: neighbors.get(aggId)?.size ?? 0,
      label: label.title,
      memberIds: members.map((m) => String(m.id)).sort(),
      aggKey: key,
      finding: members.some((m) => isFindingLinked(m as GraphNodeDatum)),
    });
  }

  // 4. Bounded seeds by priority, then complete 1-hop neighborhoods.
  // Genuine isolates (no relationships) never seed the map, and dead-end
  // inventory leaves (no/warning-free risk, <= 1 connection, no finding)
  // are not pulled in as neighbors — both stay available in Explore.
  const isLowValue = (el: Element): boolean =>
    (el.risk === "none" || el.risk === "info") && !el.finding;
  const ranked = [...elements.values()].sort(compareElements);
  const shown = new Map<string, Element>();
  for (const el of ranked.slice(0, Math.max(0, budget))) {
    if (el.degree === 0 && isLowValue(el)) continue;
    shown.set(el.id, el);
  }
  for (const seed of [...shown.values()].sort(compareElements)) {
    if (shown.size >= nodeCap) break;
    const next = [...(neighbors.get(seed.id) ?? [])]
      .filter((id) => !shown.has(id) && elements.has(id))
      .map((id) => elements.get(id)!)
      .filter((nb) => nb.finding || nb.degree > 1 || !isLowValue(nb))
      .sort(compareElements);
    for (const nb of next) {
      if (shown.size >= nodeCap) break;
      shown.set(nb.id, nb);
    }
  }

  // 5. Render nodes.
  const mapNodes: SecurityMapNode[] = [...shown.values()]
    .map((el): SecurityMapNode => {
      if (el.kind === "aggregate") {
        const title = el.label;
        return {
          id: el.id,
          kind: "aggregate",
          type: el.type,
          title,
          subtitle: `${el.memberIds.length} occurrences · worst ${el.risk}`,
          fullTitle: `${title} — ${el.memberIds.length} occurrences. Click to inspect members.`,
          risk: el.risk,
          tone: typeTone(el.type),
          count: el.memberIds.length,
          memberIds: el.memberIds,
          aggKey: el.aggKey,
          finding: el.finding,
          primary: isPrimary(el.risk, el.finding),
        };
      }
      const raw = byId.get(el.id)!;
      const label = describeNode(raw);
      return {
        id: el.id,
        kind: "single",
        type: el.type,
        title: label.title,
        subtitle: label.subtitle,
        fullTitle: `${label.title}${label.subtitle ? ` — ${label.subtitle}` : ""}`,
        risk: el.risk,
        tone: typeTone(el.type),
        count: 1,
        memberIds: [el.id],
        finding: el.finding,
        primary: isPrimary(el.risk, el.finding),
      };
    })
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // 6. Rewire edges between shown reps; collapse parallels per
  // relationship type (counts retained, types never merged).
  const bundled = new Map<
    string,
    { source: string; target: string; type: string; count: number; firstId: string }
  >();
  for (const e of cleanEdges) {
    const s = repOf(String(e.source));
    const t = repOf(String(e.target));
    if (!shown.has(s) || !shown.has(t) || s === t) continue;
    const type = str(e.type) || "related";
    // Pipes are escaped: representative ids may contain "|" themselves.
    const key = `${s.replaceAll("|", "¦")}|${type}|${t.replaceAll("|", "¦")}`;
    const cur = bundled.get(key);
    const eid = String(e.id || `${e.source}|${e.target}`);
    if (cur) cur.count += 1;
    else bundled.set(key, { source: s, target: t, type, count: 1, firstId: eid });
  }
  const mapEdges: SecurityMapEdge[] = [...bundled.values()]
    .map((b) => ({
      id: b.count === 1 ? b.firstId : `map:${b.source}¦${b.type}¦${b.target}×${b.count}`,
      source: b.source,
      target: b.target,
      type: b.type,
      count: b.count,
      ...(b.count === 1 ? { sourceEdgeId: b.firstId } : {}),
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const shownRaw = new Set<string>();
  for (const el of shown.values()) for (const id of el.memberIds) shownRaw.add(id);
  return {
    nodes: mapNodes,
    edges: mapEdges,
    totalElements: elements.size,
    hiddenElements: elements.size - shown.size,
    hiddenNodes: byId.size - shownRaw.size,
    strategy:
      `Top-${budget} elements by (risk, connectivity, name) plus 1-hop ` +
      `neighborhood completion (cap ${nodeCap}); libraries/assets aggregated ` +
      `by reliable identity with member counts retained.`,
  };
}
