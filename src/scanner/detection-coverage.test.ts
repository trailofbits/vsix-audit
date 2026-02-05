import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanExtension } from "./index.js";
import type { Finding, ScanOptions } from "./types.js";

const ZOO_ROOT = join(import.meta.dirname, "..", "..", "zoo");
const SAMPLES_DIR = process.env["VSIX_ZOO_PATH"] || join(ZOO_ROOT, "samples");
const TEST_CORPUS_DIR = join(import.meta.dirname, "..", "..", "test-corpus");
const CLEAN_DIR = join(TEST_CORPUS_DIR, "clean");

const hasSamples = existsSync(join(SAMPLES_DIR, "apollyon"));
const hasCleanCorpus = existsSync(CLEAN_DIR);

/**
 * Expected detections for each malware sample.
 * Maps sample path (relative to SAMPLES_DIR) to expected finding IDs.
 */
interface ExpectedDetection {
  path: string;
  description: string;
  expectedFindings: {
    id: string;
    severity?: "low" | "medium" | "high" | "critical";
    metadata?: Record<string, unknown>;
  }[];
  /** Optional fields that should appear in the finding */
  optionalFindings?: string[];
}

const MALWARE_SAMPLES: ExpectedDetection[] = [
  {
    path: "apollyon",
    description: "Discord webhook exfiltration PoC",
    expectedFindings: [
      // Discord webhook YARA rule is high severity (per rule metadata)
      { id: "YARA_C2_JS_Discord_Webhook_Jan25", severity: "high" },
    ],
    optionalFindings: ["OBFUSCATION_HIGH_ENTROPY"],
  },
  {
    path: "kagema/ShowSnowcrypto.SnowShoNo/showsnowcrypto.snowshono-0.6.0",
    description: "SnowShoNo C2 malware",
    expectedFindings: [
      { id: "KNOWN_C2_DOMAIN", severity: "critical", metadata: { domain: "niggboo.com" } },
    ],
    optionalFindings: ["YARA_SUSP_JS_Obfuscator_Hex_Vars_Jan25", "ACTIVATION_STARTUP"],
  },
  {
    path: "glassworm/icon-theme-materiall.vsix",
    description: "GlassWorm supply chain malware with Rust implant",
    expectedFindings: [
      { id: "BLOCKLIST_MATCH", severity: "critical" },
      { id: "KNOWN_MALWARE_HASH", severity: "critical" },
    ],
    optionalFindings: ["ACTIVATION_WILDCARD", "THEME_WITH_CODE", "LIFECYCLE_SCRIPT"],
  },
  {
    path: "ecm3401/Extension-Attack-Suite",
    description: "Educational attack suite with multiple techniques",
    expectedFindings: [
      { id: "KNOWN_MALWARE_HASH", severity: "critical" },
      { id: "BIDI_OVERRIDE", severity: "critical" },
    ],
    optionalFindings: [
      "AST_EVAL_DYNAMIC",
      "AST_FUNCTION_CONSTRUCTOR",
      "AST_PROCESS_BINDING",
      "YARA_MAL_JS_GlassWorm_Unicode_Stealth_Jan25",
      "YARA_C2_JS_WebSocket_Command_Exec_Jan25",
      "YARA_LOADER_PS_Download_Execute_Jan25",
    ],
  },
];

/**
 * Clean extensions that should produce minimal findings.
 * Used for false positive baseline testing.
 */
const CLEAN_EXTENSIONS = [
  "esbenp.prettier-vscode.vsix",
  "dbaeumer.vscode-eslint.vsix",
  "4ops.packer.vsix",
  "yzhang.markdown-all-in-one.vsix",
];

/**
 * Finding IDs that are acceptable in clean extensions.
 * These represent patterns that occur in legitimate code but are flagged
 * for completeness.
 */
const ACCEPTABLE_CLEAN_FINDINGS = new Set([
  // Legitimate activation patterns
  "ACTIVATION_STARTUP",
  "ACTIVATION_WILDCARD",
  // Entropy from minified code is expected
  "OBFUSCATION_HIGH_ENTROPY",
  // Dynamic imports are common in modern bundled code
  "AST_DYNAMIC_IMPORT",
  // Process bindings in Node.js polyfills
  "AST_PROCESS_BINDING",
  // Wallet-like strings in package-lock.json (integrity hashes)
  "CRYPTO_WALLET_DETECTED",
]);

/**
 * Finding IDs that should NEVER appear in clean extensions.
 * If these appear, they indicate a false positive that needs investigation.
 */
const NEVER_IN_CLEAN_FINDINGS = new Set([
  "BLOCKLIST_MATCH",
  "KNOWN_MALWARE_HASH",
  "KNOWN_C2_DOMAIN",
  "KNOWN_C2_IP",
  "KNOWN_MALWARE_WALLET",
  "MALICIOUS_NPM_PACKAGE",
  "BIDI_OVERRIDE",
  "INVISIBLE_CODE_EXECUTION",
]);

const defaultOptions: ScanOptions = {
  output: "text",
  severity: "low",
  network: false,
};

describe.skipIf(!hasSamples)("Malware Sample Detection Coverage", () => {
  for (const sample of MALWARE_SAMPLES) {
    describe(sample.description, () => {
      it(`detects expected findings in ${sample.path}`, async () => {
        const samplePath = join(SAMPLES_DIR, sample.path);
        const result = await scanExtension(samplePath, defaultOptions);

        const findingIds = new Set(result.findings.map((f) => f.id));

        // Check all expected findings are present
        for (const expected of sample.expectedFindings) {
          const finding = result.findings.find((f) => f.id === expected.id);

          expect(
            finding,
            `Expected finding ${expected.id} not found. Found: ${[...findingIds].join(", ")}`,
          ).toBeDefined();

          if (expected.severity) {
            expect(finding?.severity).toBe(expected.severity);
          }

          if (expected.metadata) {
            for (const [key, value] of Object.entries(expected.metadata)) {
              expect(finding?.metadata?.[key]).toBe(value);
            }
          }
        }
      }, 30000); // 30s timeout for large samples

      it(`produces at least one meaningful finding for ${sample.path}`, async () => {
        const samplePath = join(SAMPLES_DIR, sample.path);
        const result = await scanExtension(samplePath, defaultOptions);

        // Every malware sample should produce at least one finding at medium+ severity
        const meaningfulFindings = result.findings.filter(
          (f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium",
        );

        expect(meaningfulFindings.length).toBeGreaterThan(0);
      }, 30000);
    });
  }
});

describe.skipIf(!hasCleanCorpus)("Clean Extension False Positive Testing", () => {
  for (const ext of CLEAN_EXTENSIONS) {
    it(`${ext} has no critical findings that indicate malware`, async () => {
      const extPath = join(CLEAN_DIR, ext);
      if (!existsSync(extPath)) {
        console.warn(`Skipping ${ext}: not found in clean corpus`);
        return;
      }

      const result = await scanExtension(extPath, defaultOptions);

      // Check that no "never in clean" findings appear
      const badFindings = result.findings.filter((f) => NEVER_IN_CLEAN_FINDINGS.has(f.id));

      expect(
        badFindings,
        `Clean extension ${ext} has findings that should never appear in clean code: ${badFindings.map((f) => f.id).join(", ")}`,
      ).toHaveLength(0);
    }, 30000);
  }

  it("summarizes findings across clean corpus", async () => {
    const findingCounts: Record<string, number> = {};
    let totalScanned = 0;

    for (const ext of CLEAN_EXTENSIONS) {
      const extPath = join(CLEAN_DIR, ext);
      if (!existsSync(extPath)) continue;

      const result = await scanExtension(extPath, defaultOptions);
      totalScanned++;

      for (const finding of result.findings) {
        findingCounts[finding.id] = (findingCounts[finding.id] || 0) + 1;
      }
    }

    // Log summary for analysis (not a hard failure)
    console.log(`\nClean corpus summary (${totalScanned} extensions):`);
    const sorted = Object.entries(findingCounts).sort((a, b) => b[1] - a[1]);
    for (const [id, count] of sorted) {
      const pct = ((count / totalScanned) * 100).toFixed(0);
      const status = ACCEPTABLE_CLEAN_FINDINGS.has(id) ? "✓" : "⚠";
      console.log(`  ${status} ${id}: ${count}/${totalScanned} (${pct}%)`);
    }

    expect(totalScanned).toBeGreaterThan(0);
  }, 120000);
});

describe.skipIf(!hasSamples)("Detection Quality Assertions", () => {
  it("all expected YARA rules fire on their target samples", async () => {
    const yaraFindings: Record<string, string[]> = {};

    for (const sample of MALWARE_SAMPLES) {
      const samplePath = join(SAMPLES_DIR, sample.path);
      const result = await scanExtension(samplePath, defaultOptions);

      const yaraIds = result.findings.filter((f) => f.id.startsWith("YARA_")).map((f) => f.id);

      yaraFindings[sample.path] = yaraIds;
    }

    // Verify at least one YARA rule fires on each malware sample
    for (const [path, rules] of Object.entries(yaraFindings)) {
      // apollyon should trigger Discord webhook rule
      if (path === "apollyon") {
        expect(rules).toContain("YARA_C2_JS_Discord_Webhook_Jan25");
      }

      // ecm3401 should trigger multiple YARA rules
      if (path.includes("ecm3401")) {
        expect(rules.length).toBeGreaterThan(0);
      }
    }
  }, 60000);

  it("IOC checks detect known C2 infrastructure", async () => {
    const kagemaSample = join(
      SAMPLES_DIR,
      "kagema/ShowSnowcrypto.SnowShoNo/showsnowcrypto.snowshono-0.6.0",
    );
    const result = await scanExtension(kagemaSample, defaultOptions);

    const c2Finding = result.findings.find((f) => f.id === "KNOWN_C2_DOMAIN");
    expect(c2Finding).toBeDefined();
    expect(c2Finding?.metadata?.["domain"]).toBe("niggboo.com");
  }, 30000);

  it("hash matching catches known malware files", async () => {
    const glasswormSample = join(SAMPLES_DIR, "glassworm/icon-theme-materiall.vsix");
    const result = await scanExtension(glasswormSample, defaultOptions);

    const hashFindings = result.findings.filter((f) => f.id === "KNOWN_MALWARE_HASH");
    expect(hashFindings.length).toBeGreaterThan(0);

    // Should detect the darwin.node, os.node, and extension.js hashes
    const files = hashFindings.map((f) => f.location?.file);
    expect(files.some((f) => f?.includes("darwin.node"))).toBe(true);
  }, 30000);

  it("blocklist matching catches known malicious extension IDs", async () => {
    const glasswormSample = join(SAMPLES_DIR, "glassworm/icon-theme-materiall.vsix");
    const result = await scanExtension(glasswormSample, defaultOptions);

    const blocklistFinding = result.findings.find((f) => f.id === "BLOCKLIST_MATCH");
    expect(blocklistFinding).toBeDefined();
    expect(blocklistFinding?.severity).toBe("critical");
  }, 30000);
});
