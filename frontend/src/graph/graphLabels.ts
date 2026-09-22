// Context-aware graph labels built ONLY from fields present in the
// frozen backend contract. Never invents values: missing metadata falls
// back to the node's raw label.

import type { GraphNodeDatum } from "./graphTypes";

export const LABEL_MAX = 42;

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function num(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value)
    ? String(value)
    : "";
}

/** Last path segment, tolerant of "" / non-strings. */
export function basename(path: unknown): string {
  if (typeof path !== "string" || !path) return "";
  const parts = path.split(/[/\\]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "";
}

/**
 * Last two path segments (parent dir + file) for disambiguation:
 * `asymmetric/rsa.py` beats `rsa.py` when many files share a tree.
 * Falls back to basename when no parent exists.
 */
export function contextPath(path: unknown): string {
  if (typeof path !== "string" || !path) return "";
  const parts = path.split(/[/\\]/).filter(Boolean);
  if (parts.length === 0) return "";
  if (parts.length === 1) return parts[0];
  return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
}

function truncate(text: string, max: number = LABEL_MAX): string {
  const clean = text.trim().replace(/\s+/g, " ");
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function meta(node: GraphNodeDatum): Record<string, unknown> {
  return node.metadata && typeof node.metadata === "object"
    ? (node.metadata as Record<string, unknown>)
    : {};
}

function assetTitle(node: GraphNodeDatum): string {
  const m = meta(node);
  const parts = [
    str(m.canonical),
    num(m.key_size),
    str(m.mode) || str(m.curve),
  ].filter(Boolean);
  return parts.length ? parts.join("-") : str(node.label) || str(node.id);
}

function operationTitle(node: GraphNodeDatum): string {
  const m = meta(node);
  const op = str(m.operation_type);
  const proto = str(m.protocol);
  if (op && proto) return `${op} (${proto})`;
  return op || str(node.label) || str(node.id);
}

export interface NodeLabel {
  /** Primary line: most informative short name available. */
  title: string;
  /** Secondary line: type plus cheapest context (file / library). */
  subtitle: string;
}

export function describeNode(node: GraphNodeDatum): NodeLabel {
  const type = str(node.type);
  const m = meta(node);
  let title: string;
  if (type === "CryptoAsset") title = assetTitle(node);
  else if (type === "CryptoOperation") title = operationTitle(node);
  else title = str(node.label) || str(node.id);

  const context =
    contextPath(m.location_file) || str(m.library) || str(m.operation_type);
  const subtitle =
    context && context !== title ? `${type} · ${context}` : type || context;

  return { title: truncate(title), subtitle: truncate(subtitle, 56) };
}
