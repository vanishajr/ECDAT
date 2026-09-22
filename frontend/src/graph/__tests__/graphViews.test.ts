import { describe, expect, it } from "vitest";
import { filterGraphNodes, sliceForView } from "../graphViews";

const ids = ["a", "b", "c", "x"];
const edges = [
  { id: "a|uses|b", source: "a", target: "b" },
  { id: "b|uses|c", source: "b", target: "c" },
  { id: "x|uses|x", source: "x", target: "x" },
];

describe("sliceForView", () => {  it("explore returns the full filtered graph deterministically", () => {
    const first = sliceForView(ids, edges, "explore", "b");
    const second = sliceForView([...ids].reverse(), [...edges].reverse(), "explore", "b");
    expect([...first.nodeIds].sort()).toEqual(["a", "b", "c", "x"]);
    expect(first.hiddenNodes).toBe(0);
    expect(first.hiddenEdges).toBe(0);
    expect([...second.nodeIds].sort()).toEqual([...first.nodeIds].sort());
  });

  it("neighborhood keeps the selected node, neighbors, and links", () => {
    const slice = sliceForView(ids, edges, "neighborhood", "b");
    expect([...slice.nodeIds].sort()).toEqual(["a", "b", "c"]);
    expect([...slice.edgeIds].sort()).toEqual(["a|uses|b", "b|uses|c"]);
    expect(slice.hiddenNodes).toBe(1);
    expect(slice.hiddenEdges).toBe(1);
  });

  it("neighborhood without selection shows the full graph so a node can be picked", () => {
    const slice = sliceForView(ids, edges, "neighborhood", null);
    expect(slice.nodeIds.size).toBe(4);
    expect(slice.hiddenNodes).toBe(0);
    const narrowed = sliceForView(ids, edges, "neighborhood", "b");
    expect(narrowed.nodeIds.size).toBe(3);
    const back = sliceForView(ids, edges, "explore", "b");
    expect(back.nodeIds.size).toBe(4);
  });

  it("does not mutate the source graph data", () => {
    const frozenIds = Object.freeze(["a", "b"]);
    const frozenEdges = Object.freeze([
      Object.freeze({ id: "a|uses|b", source: "a", target: "b" }),
    ]);
    const before = JSON.stringify([frozenIds, frozenEdges]);
    sliceForView(frozenIds as never, frozenEdges as never, "neighborhood", "a");
    expect(JSON.stringify([frozenIds, frozenEdges])).toBe(before);
  });

  it("handles empty and malformed data safely", () => {
    expect(sliceForView([], [], "neighborhood", "a")).toEqual({
      nodeIds: new Set(),
      edgeIds: new Set(),
      hiddenNodes: 0,
      hiddenEdges: 0,
    });
    const slice = sliceForView(["a", "b"], [null, { source: "a" }] as never, "explore", null);
    expect(slice.nodeIds.size).toBe(2);
    expect(slice.edgeIds.size).toBe(0);
  });
});

describe("filterGraphNodes", () => {
  const nodes = [
    { id: "a", label: "AES-256-GCM", type: "CryptoAsset" },
    { id: "b", label: "Encrypt", type: "CryptoOperation" },
    { id: "c", label: "TLS", type: "CryptoAsset" },
  ];
  it("matches label, id, and type case-insensitively", () => {
    expect(filterGraphNodes(nodes, "aes", "All").map((n) => n.id)).toEqual(["a"]);
    expect(filterGraphNodes(nodes, "B", "All").map((n) => n.id)).toEqual(["b"]);
    expect(filterGraphNodes(nodes, "cryptoop", "All").map((n) => n.id)).toEqual(["b"]);
  });
  it("gates on type unless All", () => {
    expect(filterGraphNodes(nodes, "", "CryptoAsset").map((n) => n.id)).toEqual(["a", "c"]);
    expect(filterGraphNodes(nodes, "", "All")).toHaveLength(3);
  });
  it("combines query and type, tolerates malformed entries", () => {
    expect(filterGraphNodes(nodes, "tls", "CryptoOperation")).toEqual([]);
    expect(filterGraphNodes([null, undefined, ...nodes] as never, "", "All")).toHaveLength(3);
    expect(filterGraphNodes([], "x", "All")).toEqual([]);
  });
});
