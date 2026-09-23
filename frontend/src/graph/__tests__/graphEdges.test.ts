import { describe, expect, it } from "vitest";
import { EDGE_STYLE, edgeDisplay, edgeLabel, isLowPriority } from "../graphEdges";

describe("edgeLabel", () => {
  it("joins type and detail", () => {
    expect(
      edgeLabel({ source: "a", target: "b", type: "exposes", detail: "public HTTPS ingress" }),
    ).toBe("exposes · public HTTPS ingress");
  });
  it("keeps the full detail text without truncation", () => {
    const detail = "risky: unmaintained lib with a very long explanatory detail text";
    expect(edgeLabel({ source: "a", target: "b", type: "uses", detail })).toContain(detail);
  });
  it("returns empty string when neither type nor detail exists", () => {
    expect(edgeLabel({ source: "a", target: "b", type: "", detail: "" })).toBe("");
  });
});

describe("isLowPriority", () => {
  it("flags plain uses edges without detail", () => {
    expect(isLowPriority({ source: "a", target: "b", type: "uses", detail: "" })).toBe(true);
  });
  it("keeps annotated uses edges normal", () => {
    expect(isLowPriority({ source: "a", target: "b", type: "uses", detail: "CIR calls" })).toBe(false);
  });
  it("keeps non-uses edges normal", () => {
    expect(isLowPriority({ source: "a", target: "b", type: "protects", detail: "" })).toBe(false);
  });
});

describe("edgeDisplay", () => {
  const edge = { source: "a", target: "b", type: "uses", detail: "CIR calls" };
  it("hides the label by default", () => {
    expect(edgeDisplay(edge, false).label).toBeUndefined();
  });
  it("reveals the label when active", () => {
    expect(edgeDisplay(edge, true).label).toBe("uses · CIR calls");
  });
  it("never labels an empty relationship even when active", () => {
    expect(
      edgeDisplay({ source: "a", target: "b", type: "", detail: "" }, true).label,
    ).toBeUndefined();
  });
  it("tolerates malformed input", () => {
    expect(edgeDisplay(null as never, true)).toEqual({ label: undefined, lowPriority: false });
  });
  it("exposes three distinct style tiers", () => {
    expect(EDGE_STYLE.active.strokeWidth).toBeGreaterThan(EDGE_STYLE.base.strokeWidth);
    expect(EDGE_STYLE.base.strokeWidth).toBeGreaterThan(EDGE_STYLE.low.strokeWidth);
  });
});
