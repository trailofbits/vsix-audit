import { describe, it, expect } from "vitest";
import { scanExtension } from "./index.js";

describe("scanExtension", () => {
  it("returns a valid scan result structure", async () => {
    const result = await scanExtension("test.extension", {
      output: "text",
      severity: "low",
      network: true,
    });

    expect(result).toHaveProperty("extension");
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("metadata");
    expect(result.extension.id).toBe("test.extension");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.metadata.scannedAt).toBeDefined();
  });

  it("records scan duration in metadata", async () => {
    const result = await scanExtension("test.extension", {
      output: "text",
      severity: "low",
      network: true,
    });

    expect(typeof result.metadata.scanDuration).toBe("number");
    expect(result.metadata.scanDuration).toBeGreaterThanOrEqual(0);
  });
});
