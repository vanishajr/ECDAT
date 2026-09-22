import { describe, expect, it } from "vitest";
import {
  assetKey,
  buildSecurityMap,
  libraryKey,
} from "../graphSecurityMap";

const lib = (id: string, label: string, library: string, risk = "none") => ({
  id, type: "Library", label, risk, metadata: { library },
});
const asset = (id: string, canonical: string, extra: Record<string, unknown> = {}, risk = "low") => ({
  id, type: "CryptoAsset", label: canonical, risk, metadata: { canonical, ...extra },
});
const op = (id: string, operation_type: string, risk = "medium", rule_id = "R") => ({
  id, type: "CryptoOperation", label: operation_type, risk,
  metadata: { operation_type }, rule_id,
});

describe("aggregation keys", () => {
  it("groups libraries by label + library, assets by spec", () => {
    expect(libraryKey(lib("a", "cryptography", "cryptography") as never)).toBe(
      libraryKey(lib("b", "cryptography", "cryptography") as never),
    );
    expect(libraryKey(lib("c", "openssl", "openssl") as never)).not.toBe(
      libraryKey(lib("a", "cryptography", "cryptography") as never),
    );
    expect(libraryKey(op("o", "Encrypt") as never)).toBeNull();
    expect(
      assetKey(asset("a", "AES", { key_size: 256, mode: "GCM" }) as never),
    ).toBe(assetKey(asset("b", "AES", { key_size: 256, mode: "GCM" }) as never));
    expect(
      assetKey(asset("c", "AES", { key_size: 128, mode: "GCM" }) as never),
    ).not.toBe(assetKey(asset("a", "AES", { key_size: 256, mode: "GCM" }) as never));
    expect(assetKey(lib("l", "x", "x") as never)).toBeNull();
  });
});

const nodes = [
  lib("l1", "cryptography", "cryptography"),
  lib("l2", "cryptography", "cryptography"),
  lib("l3", "openssl", "openssl"),
  asset("a1", "AES", { key_size: 256, mode: "GCM" }, "high"),
  asset("a2", "AES", { key_size: 256, mode: "GCM" }, "low"),
  op("o1", "Encrypt", "critical", "AES-ECB"),
  op("o2", "Hash", "info"),
];
const edges = [
  { id: "o1|u|a1", source: "o1", target: "a1", type: "uses" },
  { id: "o1|d|l1", source: "o1", target: "l1", type: "depends_on" },
  { id: "o2|u|a2", source: "o2", target: "a2", type: "uses" },
  { id: "a1|u|l3", source: "a1", target: "l3", type: "uses" },
];

describe("finding-first prioritization", () => {
  const op = (id: string, risk: string, rule_id?: string) => ({
    id, type: "CryptoOperation", label: "Encrypt", risk,
    metadata: { operation_type: "Encrypt" }, ...(rule_id ? { rule_id } : {}),
  });
  const hub = { id: "lib", type: "Library", label: "L", risk: "none", metadata: {} };

  it("treats generic CRYPTOGRAPHY rules as weak signal", () => {
    const generic = buildSecurityMap(
      [op("g", "medium", "CRYPTOGRAPHY"), hub] as never,
      [{ id: "e", source: "g", target: "lib", type: "uses" }] as never,
      { budget: 5 },
    );
    const specific = buildSecurityMap(
      [op("s", "medium", "SHA-1"), hub] as never,
      [{ id: "e", source: "s", target: "lib", type: "uses" }] as never,
      { budget: 5 },
    );
    expect(generic.nodes.find((n) => n.id === "g")?.finding).toBe(false);
    expect(specific.nodes.find((n) => n.id === "s")?.finding).toBe(true);
  });

  it("withholds edgeless, finding-free nodes from the default view", () => {
    const map = buildSecurityMap(
      [op("hot", "high", "ECDSA"), { id: "iso", type: "Endpoint", label: "e", risk: "none", metadata: {} }] as never,
      [] as never,
      { budget: 5 },
    );
    expect(map.nodes.some((n) => n.id === "hot")).toBe(true);
    expect(map.nodes.some((n) => n.id === "iso")).toBe(false);
    expect(map.hiddenNodes).toBe(1);
  });

  it("prefers operations over libraries at equal risk and degree", () => {
    const map = buildSecurityMap(
      [
        { id: "lib", type: "Library", label: "L", risk: "medium", metadata: {} },
        op("operation", "medium"),
        { id: "hub", type: "Service", label: "S", risk: "info", metadata: {} },
      ] as never,
      [
        { id: "e1", source: "lib", target: "hub", type: "uses" },
        { id: "e2", source: "operation", target: "hub", type: "uses" },
      ] as never,
      { budget: 1 },
    );
    expect(map.nodes.map((n) => n.id)).toContain("operation");
  });
});

describe("buildSecurityMap", () => {
  it("aggregates repetition with member retention and counts", () => {
    const map = buildSecurityMap(nodes as never, edges as never, { budget: 10 });
    const agg = map.nodes.find((n) => n.kind === "aggregate" && n.type === "Library")!;
    expect(agg.count).toBe(2);
    expect([...agg.memberIds].sort()).toEqual(["l1", "l2"]);
    expect(agg.subtitle).toContain("2 occurrences");
    // Singleton library stays individual.
    expect(map.nodes.some((n) => n.id === "l3" && n.kind === "single")).toBe(true);
  });

  it("prioritizes risk, completes neighborhoods, stays connected", () => {
    const map = buildSecurityMap(nodes as never, edges as never, { budget: 1 });
    const ids = new Set(map.nodes.map((n) => n.id));
    // Critical op + high asset seeded; their neighbors completed.
    expect(ids.has("o1")).toBe(true);
    for (const e of map.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
    }
    expect(map.hiddenElements).toBeGreaterThan(0);
    expect(map.hiddenNodes).toBeGreaterThan(0);
  });

  it("rewires edges with counts and never merges relationship types", () => {
    const map = buildSecurityMap(nodes as never, edges as never, { budget: 10 });
    const uses = map.edges.find(
      (e) => e.source === "o1" && e.type === "uses" && e.target.startsWith("map:Asset|AES|256|GCM"),
    )!;
    expect(uses.count).toBe(1);
    expect(uses.sourceEdgeId).toBe("o1|u|a1");
    const types = new Set(map.edges.map((e) => e.type));
    expect(types.has("uses")).toBe(true);
    expect(types.has("depends_on")).toBe(true);
  });

  it("is deterministic and non-mutating", () => {
    const first = buildSecurityMap(nodes as never, edges as never, { budget: 3 });
    const second = buildSecurityMap([...nodes].reverse() as never, [...edges].reverse() as never, { budget: 3 });
    expect(second).toEqual(first);
    const frozenN = Object.freeze(nodes.map((n) => Object.freeze({ ...n })));
    const frozenE = Object.freeze(edges.map((e) => Object.freeze({ ...e })));
    const before = JSON.stringify([frozenN, frozenE]);
    buildSecurityMap(frozenN as never, frozenE as never);
    expect(JSON.stringify([frozenN, frozenE])).toBe(before);
  });

  it("handles empty and malformed inputs safely", () => {
    const empty = buildSecurityMap([], []);
    expect(empty.nodes).toEqual([]);
    expect(empty.edges).toEqual([]);
    const bad = buildSecurityMap(
      [null, { type: "Library" }, lib("l1", "c", "c")] as never,
      [null, { source: "l1", target: "ghost" }, { source: "l1", target: "l1", type: "uses", id: "s" }] as never,
    );
    // A self-loop-only, risk-free node is an isolate with no finding
    // value: withheld from the default map, never rendered broken.
    expect(bad.nodes).toEqual([]);
    expect(bad.edges).toEqual([]);
    expect(bad.hiddenNodes).toBe(1);
  });
});
