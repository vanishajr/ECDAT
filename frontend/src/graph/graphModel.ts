// Graph presentation/transformation layer: turns raw contract nodes
// into render-ready facts (type accents, type aggregates). Pure logic —
// no DOM, no React Flow. Never invents data; unknown types degrade to
// a neutral tone instead of failing.

import { GRAPH_TYPE_ORDER, RISK_RANK } from "./graphTypes";
import type { GraphNodeDatum } from "./graphTypes";

// Muted per-type accents (small bars/dots only — risk keeps the dot).
// Mirrors the dashboard's restrained earth/blue palette.
const TYPE_TONE: Record<string, string> = {
  Service: "#6586a4",
  Endpoint: "#7a6fa0",
  Library: "#a9824b",
  CertificateKey: "#a96f52",
  CryptoAsset: "#2f7d6d",
  CryptoOperation: "#5e5d58",
};

export const TYPE_TONE_FALLBACK = "#8b867d";

export interface RiskPill {
  label: string;
  className: string;
}

// Text risk cue (non-color channel for severity): tinted pill with dark
// text. Tones mirror the dashboard severity palette; "none" has no pill.
const RISK_PILL: Record<string, RiskPill> = {
  critical: { label: "CRIT", className: "bg-[#FDECEC] text-[#8b1f24]" },
  high: { label: "HIGH", className: "bg-[#F7E8E0] text-[#8a5636]" },
  medium: { label: "MED", className: "bg-[#FDF3E3] text-[#8a6414]" },
  low: { label: "LOW", className: "bg-[#F4EFDF] text-[#6f5a1e]" },
  info: { label: "INFO", className: "bg-[#EAF1F7] text-[#3d5a73]" },
};

export function riskPill(level: unknown): RiskPill | null {
  return RISK_PILL[String(level ?? "").toLowerCase()] ?? null;
}

export function typeTone(type: unknown): string {
  return TYPE_TONE[String(type ?? "")] ?? TYPE_TONE_FALLBACK;
}

export function typeOrderIndex(type: unknown): number {
  const i = GRAPH_TYPE_ORDER.indexOf(String(type ?? ""));
  return i === -1 ? GRAPH_TYPE_ORDER.length : i;
}

function worstRisk(a: string, b: string): string {
  const ra = RISK_RANK[String(a ?? "info").toLowerCase()] ?? 9;
  const rb = RISK_RANK[String(b ?? "info").toLowerCase()] ?? 9;
  return ra <= rb ? a : b;
}

export interface TypeAggregate {
  type: string;
  count: number;
  worstRisk: string;
  memberIds: string[];
}

/**
 * Honest type-level aggregation: every node lands in exactly one
 * bucket keyed by its existing `type` (unknown/empty → "Unknown").
 * Buckets sort by GRAPH_TYPE_ORDER, then alphabetically — deterministic.
 */
export function aggregateByType(nodes: GraphNodeDatum[]): TypeAggregate[] {
  const buckets = new Map<string, TypeAggregate>();
  for (const n of nodes) {
    if (!n || typeof n !== "object") continue;
    const id = n.id == null ? "" : String(n.id);
    if (!id) continue;
    const type =
      typeof n.type === "string" && n.type !== "" ? n.type : "Unknown";
    const risk =
      typeof n.risk === "string" && n.risk !== "" ? n.risk : "info";
    const bucket = buckets.get(type);
    if (bucket) {
      bucket.count += 1;
      bucket.memberIds.push(id);
      bucket.worstRisk = worstRisk(bucket.worstRisk, risk);
    } else {
      buckets.set(type, { type, count: 1, worstRisk: risk, memberIds: [id] });
    }
  }
  return [...buckets.values()].sort(
    (a, b) =>
      typeOrderIndex(a.type) - typeOrderIndex(b.type) ||
      a.type.localeCompare(b.type),
  );
}
