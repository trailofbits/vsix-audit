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

      const discordFinding = result.findings.find((f) => f.id === "DISCORD_WEBHOOK");
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

    it("detects SSH theft in Extension-Attack-Suite", async () => {
      const result = await scanExtension(
        join(SAMPLES_DIR, "ecm3401/Extension-Attack-Suite"),
        defaultOptions,
      );

      expect(result.extension.publisher).toBe("ecm3401");

      const sshFinding = result.findings.find((f) => f.id === "SSH_KEY_ACCESS");
      expect(sshFinding).toBeDefined();
      expect(sshFinding?.severity).toBe("high");
      expect(sshFinding?.location?.file).toBe("src/func_steal_ssh.ts");

      const hashFinding = result.findings.find((f) => f.id === "KNOWN_MALWARE_HASH");
      expect(hashFinding).toBeDefined();
      expect(hashFinding?.severity).toBe("critical");
    });

    it("detects hidden PowerShell in Extension-Attack-Suite", async () => {
      const result = await scanExtension(
        join(SAMPLES_DIR, "ecm3401/Extension-Attack-Suite"),
        defaultOptions,
      );

      const psFinding = result.findings.find((f) => f.id === "POWERSHELL_HIDDEN");
      expect(psFinding).toBeDefined();
      expect(psFinding?.severity).toBe("critical");
    });
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
