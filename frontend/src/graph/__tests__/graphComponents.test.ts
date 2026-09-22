import { describe, expect, it } from "vitest";
import { connectedComponents } from "../graphComponents";

describe("connectedComponents", () => {
  it("finds components, isolates, and orders deterministically", () => {
    const first = connectedComponents(
      ["a", "b", "c", "solo"],
      [
        { source: "a", target: "b" },
        { source: "b", target: "c" },
      ],
    );
    expect(first).toHaveLength(2);
    expect(first[0].members).toEqual(["a", "b", "c"]);
    expect(first[0].isolated).toBe(false);
    expect(first[1]).toEqual({ root: "solo", members: ["solo"], isolated: true });
    const second = connectedComponents(
      ["solo", "c", "b", "a"],
      [
        { source: "c", target: "b" },
        { source: "a", target: "b" },
      ],
    );
    expect(second).toEqual(first);
  });

  it("treats self-loops as linked but single-member", () => {
    const [only] = connectedComponents(["a"], [{ source: "a", target: "a" }]);
    expect(only.members).toEqual(["a"]);
    expect(only.isolated).toBe(false);
  });

  it("skips dangling and malformed edges without throwing", () => {
    const comps = connectedComponents(["a", "b"], [
      { source: "a", target: "ghost" },
      null as never,
      { source: "", target: "b" } as never,
    ]);
    expect(comps).toHaveLength(2);
    expect(comps.every((c) => c.isolated)).toBe(true);
  });

  it("handles empty input", () => {
    expect(connectedComponents([], [])).toEqual([]);
  });
});
