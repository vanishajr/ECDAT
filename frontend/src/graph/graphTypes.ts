// Types mirroring the frozen backend graph contract
// (ecdat/adapters/graph_adapter.py). Frontend reads only — never reshape here.

export type GraphNodeType =
  | "Service"
  | "Endpoint"
  | "Library"
  | "CertificateKey"
  | "CryptoAsset"
  | "CryptoOperation";

export type GraphRisk =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "none";

export interface GraphNodeDatum {
  id: string;
  type: string;
  label: string;
  risk: string;
  confidence?: number | null;
  metadata?: Record<string, unknown>;
  rule_id?: string;
}

export interface GraphEdgeDatum {
  id?: string;
  source: string;
  target: string;
  type: string;
  detail?: string;
}

export interface FrontendGraph {
  nodes: GraphNodeDatum[];
  edges: GraphEdgeDatum[];
  folded_files?: string[];
  trace_paths?: unknown[];
}

export const GRAPH_TYPE_ORDER: string[] = [
  "Service",
  "Endpoint",
  "Library",
  "CertificateKey",
  "CryptoAsset",
  "CryptoOperation",
];

export const GRAPH_INIT_LIMIT = 150;
export const GRAPH_EDGE_LIMIT = 500;

export const RISK_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  none: 5,
};

export function riskRankOf(risk: unknown): number {
  return RISK_RANK[String(risk ?? "info").toLowerCase()] ?? 9;
}
