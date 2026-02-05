import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanExtension } from "./index.js";

const ZOO_ROOT = join(import.meta.dirname, "..", "..", "zoo");
const SAMPLES_DIR = process.env["VSIX_ZOO_PATH"] || join(ZOO_ROOT, "samples");
const hasSamples = existsSync(join(SAMPLES_DIR, "apollyon"));

describe("scanExtension", () => {
  const defaultOptions = {
    output: "text" as const,
    severity: "low" as const,
    network: true,
  };

  it("throws error for non-existent target", async () => {
    await expect(scanExtension("nonexistent.vsix", defaultOptions)).rejects.toThrow(
      "Target not found: nonexistent.vsix",
    );
  });

  describe.skipIf(!hasSamples)("zoo sample detection", () => {
    it("detects Discord webhook in apollyon sample", async () => {
      const result = await scanExtension(join(SAMPLES_DIR, "apollyon"), defaultOptions);

      expect(result.extension.publisher).toBeUndefined();
      expect(result.extension.name).toBe("mal-vscode-poc");

      // Discord webhook detection via YARA rule
      const discordFinding = result.findings.find(
        (f) => f.id === "YARA_C2_JS_Discord_Webhook_Jan25",
      );
      expect(discordFinding).toBeDefined();
      expect(discordFinding?.severity).toBe("high");
      expect(discordFinding?.location?.file).toBe("extension.js");
    });

    it("detects C2 domain in kagema sample", async () => {
      const result = await scanExtension(
        join(SAMPLES_DIR, "kagema/ShowSnowcrypto.SnowShoNo/showsnowcrypto.snowshono-0.6.0"),
        defaultOptions,
      );

      expect(result.extension.publisher).toBe("ShowSnowcrypto");

      const c2Finding = result.findings.find((f) => f.id === "KNOWN_C2_DOMAIN");
      expect(c2Finding).toBeDefined();
      expect(c2Finding?.severity).toBe("critical");
      expect(c2Finding?.metadata?.["domain"]).toBe("niggboo.com");
    });

    it("detects malware hash and trojan source in Extension-Attack-Suite", async () => {
      const result = await scanExtension(
        join(SAMPLES_DIR, "ecm3401/Extension-Attack-Suite"),
        defaultOptions,
      );

      expect(result.extension.publisher).toBe("ecm3401");

      // Should detect known malware hash for the .vsix file
      const hashFinding = result.findings.find((f) => f.id === "KNOWN_MALWARE_HASH");
      expect(hashFinding).toBeDefined();
      expect(hashFinding?.severity).toBe("critical");

      // Should detect Trojan Source (BIDI override) attack
      const bidiFinding = result.findings.find((f) => f.id === "BIDI_OVERRIDE");
      expect(bidiFinding).toBeDefined();
      expect(bidiFinding?.severity).toBe("critical");
    }, 30000);

    it("detects PowerShell loader in Extension-Attack-Suite", async () => {
      const result = await scanExtension(
        join(SAMPLES_DIR, "ecm3401/Extension-Attack-Suite"),
        defaultOptions,
      );

      // PowerShell download/execute pattern via YARA (critical severity per rule metadata)
      const psFinding = result.findings.find(
        (f) => f.id === "YARA_LOADER_PS_Download_Execute_Jan25",
      );
      expect(psFinding).toBeDefined();
      expect(psFinding?.severity).toBe("critical");
    }, 30000);
  });

  describe.skipIf(!hasSamples)("severity filtering", () => {
    it("filters findings by minimum severity", async () => {
      const lowResult = await scanExtension(join(SAMPLES_DIR, "apollyon"), {
        ...defaultOptions,
        severity: "low",
      });

      const highResult = await scanExtension(join(SAMPLES_DIR, "apollyon"), {
        ...defaultOptions,
        severity: "high",
      });

      expect(highResult.findings.length).toBeLessThanOrEqual(lowResult.findings.length);
      expect(
        highResult.findings.every((f) => f.severity === "high" || f.severity === "critical"),
      ).toBe(true);
    });
  });
});
