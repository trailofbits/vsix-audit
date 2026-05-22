import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
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

  it("disables threat intelligence without disabling generic detections", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vsix-audit-no-intel-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({
          name: "no-intel-fixture",
          publisher: "test",
          version: "1.0.0",
          main: "main.js",
          dependencies: {
            "vscode-darcula": "1.0.0",
          },
        }),
      );
      await writeFile(
        join(dir, "main.js"),
        [
          'const c2 = "niggboo.com";',
          'const cmd = "npx github:nrwl/nx#0123456789abcdef0123456789abcdef01234567";',
          "console.log(c2, cmd);",
        ].join("\n"),
      );

      const withIntel = await scanExtension(dir, defaultOptions);
      const withoutIntel = await scanExtension(dir, { ...defaultOptions, intel: "none" });

      expect(withIntel.findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(true);
      expect(withIntel.findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(true);
      expect(withIntel.findings.some((f) => f.id === "GITHUB_SHA_EXECUTION")).toBe(true);

      expect(withoutIntel.metadata.intel).toBe("none");
      expect(withoutIntel.findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(false);
      expect(withoutIntel.findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(false);
      expect(withoutIntel.findings.some((f) => f.id === "GITHUB_SHA_EXECUTION")).toBe(true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
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
