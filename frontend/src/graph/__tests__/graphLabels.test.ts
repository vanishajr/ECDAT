import { describe, expect, it } from "vitest";
import { basename, contextPath, describeNode } from "../graphLabels";
import type { GraphNodeDatum } from "../graphTypes";

const base = (over: Partial<GraphNodeDatum>): GraphNodeDatum => ({
  id: "n1",
  type: "Service",
  label: "svc",
  risk: "info",
  ...over,
});

describe("basename", () => {
  it("returns the last segment", () => {
    expect(basename("a/b/tls.c")).toBe("tls.c");
  });
  it("tolerates empty and non-string input", () => {
    expect(basename("")).toBe("");
    expect(basename(undefined)).toBe("");
    expect(basename(42)).toBe("");
  });
});

describe("contextPath", () => {
  it("keeps parent directory plus file", () => {
    expect(contextPath("a/asymmetric/rsa.py")).toBe("asymmetric/rsa.py");
  });
  it("falls back to basename without a parent", () => {
    expect(contextPath("rsa.py")).toBe("rsa.py");
    expect(contextPath("")).toBe("");
    expect(contextPath(undefined)).toBe("");
  });
});

describe("describeNode", () => {
  it("builds AES-128-GCM from asset metadata", () => {
    const out = describeNode(
      base({
        type: "CryptoAsset",
        label: "AES",
        metadata: { canonical: "AES", key_size: 128, mode: "GCM" },
      }),
    );
    expect(out.title).toBe("AES-128-GCM");
  });

  it("prefers curve when mode is absent", () => {
    const out = describeNode(
      base({
        type: "CryptoAsset",
        label: "ECDH",
        metadata: { canonical: "ECDH", curve: "P-256" },
      }),
    );
    expect(out.title).toBe("ECDH-P-256");
  });

  it("falls back to raw label when asset metadata is missing", () => {
    const out = describeNode(base({ type: "CryptoAsset", label: "DH" }));
    expect(out.title).toBe("DH");
  });

  it("combines operation type and protocol", () => {
    const out = describeNode(
      base({
        type: "CryptoOperation",
        label: "Encrypt",
        metadata: { operation_type: "Encrypt", protocol: "TLS" },
      }),
    );
    expect(out.title).toBe("Encrypt (TLS)");
  });

  it("puts the source file in the subtitle, not the title", () => {
    const out = describeNode(
      base({
        type: "CryptoOperation",
        label: "Encrypt",
        metadata: { operation_type: "Encrypt", location_file: "ssl/tls.c" },
      }),
    );
    expect(out.title).toBe("Encrypt");
    expect(out.subtitle).toContain("tls.c");
  });

  it("never invents data for bare nodes", () => {
    const out = describeNode(base({ label: "DH" }));
    expect(out.title).toBe("DH");
    expect(out.subtitle).toBe("Service");
  });

  it("truncates very long labels", () => {
    const out = describeNode(base({ label: "x".repeat(100) }));
    expect(out.title.length).toBeLessThanOrEqual(42);
  });
});
