import { describe, expect, it } from "vitest";
import { contentBounds, fallbackLayout, layoutGraph, layoutPacked } from "../graphLayout";

const chain = [{ id: "a" }, { id: "b" }, { id: "c" }];
const chainEdges = [
  { source: "a", target: "b" },
  { source: "b", target: "c" },
];

describe("layoutGraph", () => {
  it("resolves empty input without calling ELK", async () => {
    let called = false;
    const out = await layoutGraph([], [], {
      layout: async () => {
        called = true;
        return {};
      },
    });
    expect(out).toEqual([]);
    expect(called).toBe(false);
  });

  it("skips malformed nodes and edges dangling outside the set", async () => {
    const out = await layoutGraph(
      [{ id: "a" }, { id: "" }, null as never, { id: "b" }],
      [
        { source: "a", target: "b" },
        { source: "a", target: "ghost" },
      ],
    );
    expect(out.map((p) => p.id).sort()).toEqual(["a", "b"]);
  });

  it("positions every node deterministically", async () => {
    const first = await layoutGraph(chain, chainEdges);
    const second = await layoutGraph(
      [...chain].reverse(),
      [...chainEdges].reverse(),
    );
    expect(first).toHaveLength(3);
    expect(second).toEqual(first);
    const as = first.find((p) => p.id === "a")!;
    const cs = first.find((p) => p.id === "c")!;
    expect(cs.y).toBeGreaterThan(as.y);
  });

  it("falls back to a deterministic grid when ELK fails", async () => {
    const failing = {
      layout: async () => {
        throw new Error("elk down");
      },
    };
    const first = await layoutGraph(chain, chainEdges, failing);
    const second = await layoutGraph(chain, chainEdges, failing);
    expect(first).toHaveLength(3);
    expect(first).toEqual(second);
    expect(first).toEqual(fallbackLayout(["a", "b", "c"]));
  });
});

describe("layoutPacked", () => {
  const nodes = [{ id: "a" }, { id: "b" }, { id: "s1" }, { id: "s2" }];
  const edges = [{ source: "a", target: "b" }];

  it("packs components without overlap, deterministically", async () => {
    // Geometry check via an injected ELK double (honest 288px pitch).
    const box = {
      layout: async (g: any) => ({
        children: (g.children ?? []).map((c: any, i: number) => ({
          id: c.id,
          x: i * 288,
          y: 0,
        })),
      }),
    };
    const first = await layoutPacked(nodes, edges, box);
    const second = await layoutPacked([...nodes].reverse(), [...edges], box);
    expect(first).toEqual(second);
    expect(first.map((p) => p.id).sort()).toEqual(["a", "b", "s1", "s2"]);
    // Bounding boxes (240x72 nodes) must not overlap.
    const boxes = first.map((p) => ({ ...p, w: 240, h: 72 }));
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const overlap =
          boxes[i].x < boxes[j].x + boxes[j].w &&
          boxes[j].x < boxes[i].x + boxes[i].w &&
          boxes[i].y < boxes[j].y + boxes[i].h &&
          boxes[j].y < boxes[i].y + boxes[i].h;
        expect(overlap).toBe(false);
      }
    }
  });

  it("handles all-isolated and empty inputs", async () => {
    let called = false;
    const spy = {
      layout: async () => {
        called = true;
        return { children: [] };
      },
    };
    const out = await layoutPacked([{ id: "x" }, { id: "y" }], [], spy);
    expect(called).toBe(false);
    expect(out.map((p) => p.id).sort()).toEqual(["x", "y"]);
    expect(await layoutPacked([], [], spy)).toEqual([]);
  });
  it("forwards per-node sizes to ELK", async () => {
    let seen: any = null;
    const capture = {
      layout: async (g: any) => {
        seen = g;
        return {
          children: (g.children ?? []).map((c: any) => ({ id: c.id, x: 0, y: 0 })),
        };
      },
    };
    await layoutGraph(
      [
        { id: "big", width: 240, height: 78 },
        { id: "small", width: 208, height: 64 },
      ],
      [{ source: "big", target: "small" }],
      capture,
    );
    const byId = new Map(seen.children.map((c: any) => [c.id, c]));
    expect(byId.get("big")).toMatchObject({ width: 240, height: 78 });
    expect(byId.get("small")).toMatchObject({ width: 208, height: 64 });
  });
});

describe("contentBounds", () => {  it("measures extents including node size", () => {
    const b = contentBounds([
      { id: "a", x: 20, y: 20 },
      { id: "b", x: 300, y: 100 },
    ]);
    expect(b.minX).toBe(20);
    expect(b.minY).toBe(20);
    expect(b.maxX).toBe(300 + 240);
    expect(b.maxY).toBe(100 + 72);
    expect(b.width).toBe(520);
    expect(b.centerX).toBe((20 + 540) / 2);
  });

  it("packs disconnected components into compact rows", async () => {
    // Three disconnected 10-node chains through the honest-pitch
    // double: each chain is 1392 wide, so packing must stack them in
    // three rows (3 * 240 height + 2 * 48 pads = 816) instead of one
    // 1392-wide strip beside oceans of whitespace.
    const box = {
      layout: async (g: any) => ({
        children: (g.children ?? []).map((c: any, i: number) => ({
          id: c.id,
          x: (i % 5) * 288,
          y: Math.floor(i / 5) * 168,
        })),
      }),
    };
    const ids: Array<{ id: string }> = [];
    const chainEdges: Array<{ source: string; target: string }> = [];
    for (let c = 0; c < 3; c++) {
      for (let i = 0; i < 10; i++) ids.push({ id: `c${c}n${i}` });
      for (let i = 0; i < 9; i++) {
        chainEdges.push({ source: `c${c}n${i}`, target: `c${c}n${i + 1}` });
      }
    }
    const out = await layoutPacked(ids, chainEdges, box);
    expect(out).toHaveLength(30);
    const b = contentBounds(out);
    expect(b.width).toBe(1392);
    expect(b.height).toBe(816);
  });

  it("returns a zero box for empty input", () => {
    expect(contentBounds([])).toEqual({
      minX: 0, minY: 0, maxX: 0, maxY: 0, width: 0, height: 0, centerX: 0, centerY: 0,
    });
  });
});
