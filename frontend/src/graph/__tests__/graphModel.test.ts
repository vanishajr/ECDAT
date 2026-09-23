import { describe, expect, it } from "vitest";
import { aggregateByType, riskPill, typeTone, TYPE_TONE_FALLBACK } from "../graphModel";

const nodes = [
  { id: "s1", type: "Service", label: "api", risk: "high" },
  { id: "s2", type: "Service", label: "web", risk: "low" },
  { id: "a1", type: "CryptoAsset", label: "AES", risk: "critical" },
  { id: "weird", type: "Container", label: "c", risk: "info" },
  { id: "notype", type: "", label: "n", risk: "info" },
];

describe("typeTone", () => {
  it("returns a distinct accent per known type", () => {
    expect(typeTone("Service")).not.toBe(typeTone("Library"));
  });
  it("falls back to neutral for unknown types", () => {
    expect(typeTone("Container")).toBe(TYPE_TONE_FALLBACK);
    expect(typeTone(undefined)).toBe(TYPE_TONE_FALLBACK);
  });
});

describe("aggregateByType", () => {
  it("counts members and keeps the worst risk", () => {
    const aggs = aggregateByType(nodes);
    const svc = aggs.find((a) => a.type === "Service")!;
    expect(svc.count).toBe(2);
    expect(svc.worstRisk).toBe("high");
    expect([...svc.memberIds].sort()).toEqual(["s1", "s2"]);
  });

  it("covers every node exactly once, including unknown types", () => {
    const aggs = aggregateByType(nodes);
    const total = aggs.reduce((n, a) => n + a.count, 0);
    expect(total).toBe(nodes.length);
    const all = aggs.flatMap((a) => a.memberIds);
    expect(new Set(all).size).toBe(nodes.length);
    expect(aggs.some((a) => a.type === "Unknown")).toBe(true);
  });

  it("orders by GRAPH_TYPE_ORDER deterministically", () => {
    const first = aggregateByType(nodes).map((a) => a.type);
    const second = aggregateByType([...nodes].reverse()).map((a) => a.type);
    expect(first).toEqual(second);
    expect(first.indexOf("Service")).toBeLessThan(first.indexOf("CryptoAsset"));
  });

  it("handles empty and malformed input without throwing", () => {
    expect(aggregateByType([])).toEqual([]);
    expect(aggregateByType([null, { type: "Service" }] as never)).toEqual([]);
  });

  it("does not mutate the input", () => {
    const frozen = Object.freeze(nodes.map((n) => Object.freeze({ ...n })));
    const before = JSON.stringify(frozen);
    aggregateByType(frozen as never);
    expect(JSON.stringify(frozen)).toBe(before);
  });
});

describe("riskPill", () => {
  it("labels severities with pill classes", () => {
    expect(riskPill("high")).toMatchObject({ label: "HIGH" });
    expect(riskPill("MEDIUM")?.label).toBe("MED");
    expect(riskPill("critical")?.label).toBe("CRIT");
  });
  it("returns null for none and unknown levels", () => {
    expect(riskPill("none")).toBeNull();
    expect(riskPill("bogus")).toBeNull();
    expect(riskPill(undefined)).toBeNull();
  });
});
