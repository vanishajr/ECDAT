import { describe, expect, it } from "vitest";
import { neighborhood } from "../graphFocus";

const edges = [
  { id: "a|uses|b", source: "a", target: "b", type: "uses" },
  { id: "b|uses|c", source: "b", target: "c", type: "uses" },
  { id: "c|uses|c", source: "c", target: "c", type: "uses" },
  { id: "x|uses|y", source: "x", target: "y", type: "uses" },
];

describe("neighborhood", () => {
  it("keeps the selected node plus 1-hop neighbors both ways", () => {
    const { keep, edgeKeep } = neighborhood("b", edges);
    expect([...keep].sort()).toEqual(["a", "b", "c"]);
    expect([...edgeKeep].sort()).toEqual(["a|uses|b", "b|uses|c"]);
  });

  it("does not leak unrelated subgraphs", () => {
    const { keep } = neighborhood("b", edges);
    expect(keep.has("x")).toBe(false);
    expect(keep.has("y")).toBe(false);
  });

  it("handles self-loops without duplicating", () => {
    const { keep, edgeKeep } = neighborhood("c", edges);
    expect([...keep].sort()).toEqual(["b", "c"]);
    expect(edgeKeep.has("c|uses|c")).toBe(true);
  });

  it("returns empty sets for null selection (no focus)", () => {
    const { keep, edgeKeep } = neighborhood(null, edges);
    expect(keep.size).toBe(0);
    expect(edgeKeep.size).toBe(0);
  });

  it("ignores malformed and dangling edges without throwing", () => {
    const bad: unknown[] = [
      null,
      { source: "b" },
      { source: "", target: "b" },
      { source: "b", target: "missing" },
    ];
    const { keep } = neighborhood(
      "b",
      bad as never,
    );
    expect([...keep].sort()).toEqual(["b", "missing"]);
  });

  it("does not mutate the input edge list", () => {
    const frozen = Object.freeze(edges.map((e) => Object.freeze({ ...e })));
    const before = JSON.stringify(frozen);
    neighborhood("b", frozen as never);
    expect(JSON.stringify(frozen)).toBe(before);
  });
});
