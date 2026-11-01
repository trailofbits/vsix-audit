import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest } from "#internal/scanner/types.js";
import { checkAST } from "#internal/scanner/checks/ast.js";

describe("dynamic arguments", () => {
  it.each([
    ["eval", "AST_EVAL_DYNAMIC"],
    ["require", "AST_DYNAMIC_REQUIRE"],
    ["import", "AST_DYNAMIC_IMPORT"],
  ])("distinguishes static and interpolated templates for %s", (callee, id) => {
    const constant = makeContents({ "main.js": `${callee}(\`fixed\`);` });
    const dynamic = makeContents({ "main.js": `${callee}(\`prefix\${remote}\`);` });
    expect(checkAST(constant).findings.map((finding) => finding.id)).not.toContain(id);
    expect(checkAST(dynamic).findings.map((finding) => finding.id)).toContain(id);
  });

  it.each(["main.js", "main.min.js", "vendor/main.js", "node_modules/fixture/main.js"])(
    "retains dynamic execution evidence in %s",
    (filename) => {
      expect(checkAST(makeContents({ [filename]: "eval(payload);" })).findings).toContainEqual(
        expect.objectContaining({ id: "AST_EVAL_DYNAMIC" }),
      );
    },
  );
});

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

describe("checkAST", () => {
  it.each([
    ["main.ts", "const code: string = payload; eval(code);"],
    ["MAIN.TS", "const code: string = payload; eval(code);"],
    ["main.tsx", "const code: string = payload; eval(code);"],
    ["MAIN.TSX", "const code: string = payload; eval(code);"],
    ["main.jsx", "const node = <div>{eval(payload)}</div>;"],
    ["MAIN.JSX", "const node = <div>{eval(payload)}</div>;"],
  ])("recognizes language modes regardless of extension case in %s", (filename, source) => {
    const result = checkAST(makeContents({ [filename]: source }));
    expect(result.warnings).toEqual([]);
    const finding = result.findings.find((entry) => entry.id === "AST_EVAL_DYNAMIC");
    expect(finding?.location).toMatchObject({ file: filename, line: 1 });
  });

  it("parses bundled TypeScript declarations in declaration mode", () => {
    const result = checkAST(
      makeContents({
        "node_modules/example/index.d.ts": "export const version: string;",
        "node_modules/example/index.ts": "export const version = '1.0.0';",
      }),
    );
    expect(result.warnings).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  // ============================================================================
  // EVAL DETECTION
  // ============================================================================

  describe("eval() detection", () => {
    it("detects eval with dynamic argument", () => {
      const content = `
        const code = getUserInput();
        eval(code);
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("ignores eval with string literal", () => {
      const content = `eval("console.log('hello')");`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(false);
    });

    it("detects globalThis.eval access", () => {
      const content = `globalThis.eval(code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_GLOBAL_THIS_EVAL")).toBe(true);
    });

    it("detects window.eval access", () => {
      const content = `window["eval"](code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_GLOBAL_THIS_EVAL")).toBe(true);
    });
  });

  // ============================================================================
  // FUNCTION CONSTRUCTOR DETECTION
  // ============================================================================

  describe("Function() constructor detection", () => {
    it.each(['new Function("", payload);', 'new Function("", "return process.env;");'])(
      "retains execution evidence when an empty parameter precedes the body: %s",
      (source) => {
        const findings = checkAST(makeContents({ "extension.js": source })).findings;
        expect(findings.some((finding) => finding.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
      },
    );

    it("ignores an empty literal body used as a code-generation feature probe", () => {
      const contents = makeContents({
        "extension.js":
          "const supported = (() => {" +
          ' try { return new Function(""); } catch { return false; }' +
          " })();",
      });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(false);
    });

    it("detects new Function() with dynamic argument", () => {
      const content = `
        const body = getCode();
        const fn = new Function('arg', body);
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });

    it("detects new Function() with literal argument", () => {
      // Even literal arguments are flagged (unless bundled) because
      // Function() is dangerous and rarely needed
      const content = `const fn = new Function('return 1');`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });
  });

  // ============================================================================
  // DYNAMIC REQUIRE/IMPORT DETECTION
  // ============================================================================

  describe("dynamic require() detection", () => {
    it("detects require with variable argument", () => {
      const content = `
        const moduleName = getModuleName();
        require(moduleName);
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_DYNAMIC_REQUIRE")).toBe(true);
    });

    it("ignores require with string literal", () => {
      const content = `require("fs");`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_DYNAMIC_REQUIRE")).toBe(false);
    });
  });

  describe("dynamic import() detection", () => {
    it("detects import() with variable argument", () => {
      const content = `
        const path = getPath();
        import(path);
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_DYNAMIC_IMPORT")).toBe(true);
    });

    it("ignores import() with string literal", () => {
      const content = `import("./module.js");`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_DYNAMIC_IMPORT")).toBe(false);
    });
  });

  // ============================================================================
  // PROCESS.BINDING DETECTION
  // ============================================================================

  describe("process.binding detection", () => {
    it("detects process.binding() call", () => {
      const content = `process.binding('fs');`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_PROCESS_BINDING")).toBe(true);
    });

    it("detects process._linkedBinding() call", () => {
      const content = `process._linkedBinding('config');`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_PROCESS_BINDING")).toBe(true);
    });
  });

  // ============================================================================
  // NODE_MODULES EXCLUSIONS
  // ============================================================================

  describe("dependency coverage", () => {
    it("retains evidence for eval detection in node_modules", () => {
      const content = `
        const code = getUserInput();
        eval(code);
      `;
      const contents = makeContents({ "node_modules/protobufjs/src/parse.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("retains evidence for Function constructor detection in node_modules", () => {
      const content = `const fn = new Function('arg', body);`;
      const contents = makeContents({ "node_modules/@babel/core/lib/transform.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });

    it("retains evidence for process.binding detection in node_modules", () => {
      const content = `process.binding('fs');`;
      const contents = makeContents({ "node_modules/graceful-fs/polyfills.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_PROCESS_BINDING")).toBe(true);
    });

    it("retains evidence for dynamic require in node_modules", () => {
      const content = `require(modulePath);`;
      const contents = makeContents({ "node_modules/pino/lib/logger.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_DYNAMIC_REQUIRE")).toBe(true);
    });

    it("retains evidence for vendor directory", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "vendor/third-party/lib.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });
  });

  // ============================================================================
  // BUNDLED CODE EXCLUSIONS
  // ============================================================================

  describe("bundled code coverage", () => {
    it("retains evidence for eval in webpack bundled code", () => {
      // Webpack bundles have characteristic patterns
      const content = `
        /******/ (function(modules) { // webpackBootstrap
        /******/   function __webpack_require__(moduleId) {
        /******/   }
        /******/ })
        eval(__webpack_require__.m[moduleId]);
      `;
      const contents = makeContents({ "dist/bundle.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("retains evidence for Function constructor in rollup bundled code", () => {
      // Rollup detection requires (function (exports AND Object.defineProperty(exports,
      const content = `
        (function (exports) {
          'use strict';
          Object.defineProperty(exports, '__esModule', { value: true });
          const fn = new Function('return this')();
          exports.default = fn;
        })();
      `;
      const contents = makeContents({ "dist/bundle.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });

    it("still detects eval in bundled code WITH obfuscation", () => {
      // If bundled code also has obfuscation indicators, flag it
      const content = `
        /******/ (function(modules) { // webpackBootstrap
        /******/ })
        var _0x4a2b = ['ZXZhbA=='];
        eval(atob(_0x4a2b[0]));
      `;
      const contents = makeContents({ "dist/bundle.js": content });

      const findings = checkAST(contents).findings;

      // Should be flagged because of obfuscation indicators
      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("still detects Function constructor in bundled code WITH obfuscation", () => {
      const content = `
        var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};
        var _0x1234 = ['return this'];
        const fn = new Function(atob(_0x1234[0]))();
      `;
      const contents = makeContents({ "dist/bundle.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });
  });

  // ============================================================================
  // AUTHOR CODE DETECTION (STILL WORKS)
  // ============================================================================

  describe("author code detection", () => {
    it("detects eval in extension source code", () => {
      const content = `
        function runUserCode(code) {
          return eval(code);
        }
      `;
      const contents = makeContents({ "src/extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("detects eval in out directory (compiled but not bundled)", () => {
      const content = `
        function dangerous(input) {
          eval(input);
        }
      `;
      const contents = makeContents({ "out/extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_EVAL_DYNAMIC")).toBe(true);
    });

    it("detects Function constructor in author code", () => {
      const content = `const fn = new Function('arg', body);`;
      const contents = makeContents({ "lib/compiler.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.some((f) => f.id === "AST_FUNCTION_CONSTRUCTOR")).toBe(true);
    });
  });

  // ============================================================================
  // FILE TYPE FILTERING
  // ============================================================================

  describe("file type filtering", () => {
    it("scans .js files", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .ts files", () => {
      const content = `eval(code as string);`;
      const contents = makeContents({ "extension.ts": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .mjs files", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "extension.mjs": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .cjs files", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "extension.cjs": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .jsx files", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "component.jsx": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .tsx files", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "component.tsx": content });

      const findings = checkAST(contents).findings;
      expect(findings.length).toBeGreaterThan(0);
    });

    it("ignores .json files", () => {
      const content = `{"eval": "code"}`;
      const contents = makeContents({ "config.json": content });

      const findings = checkAST(contents).findings;
      expect(findings).toHaveLength(0);
    });

    it("ignores .md files", () => {
      const content = `eval(code) is dangerous`;
      const contents = makeContents({ "README.md": content });

      const findings = checkAST(contents).findings;
      expect(findings).toHaveLength(0);
    });
  });

  // ============================================================================
  // METADATA AND LOCATION
  // ============================================================================

  describe("metadata", () => {
    it("includes code snippet in metadata", () => {
      const content = `eval(maliciousCode);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.metadata?.["codeSnippet"]).toContain("eval");
    });

    it("includes legitimate uses in metadata", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.metadata?.["legitimateUses"]).toBeDefined();
    });

    it("includes red flags in metadata", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.metadata?.["redFlags"]).toBeDefined();
    });

    it("includes line number in location", () => {
      const content = `// line 1\n// line 2\neval(code);`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.location?.line).toBe(3);
    });

    it("includes file path in location", () => {
      const content = `eval(code);`;
      const contents = makeContents({ "src/dangerous.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.location?.file).toBe("src/dangerous.js");
    });
  });

  // ============================================================================
  // CATEGORY ASSIGNMENT
  // ============================================================================

  describe("category assignment", () => {
    it("assigns ast category to all findings", () => {
      const content = `
        eval(code);
        new Function(body);
        process.binding('fs');
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkAST(contents).findings;

      expect(findings.every((f) => f.category === "ast")).toBe(true);
    });
  });

  // ============================================================================
  // PARSE ERROR HANDLING
  // ============================================================================

  describe("parse error handling", () => {
    it("handles files with syntax errors gracefully", () => {
      const content = `function broken( { eval(code) }`;
      const contents = makeContents({ "broken.js": content });

      const findings = checkAST(contents).findings;
      expect(Array.isArray(findings)).toBe(true);
      const failure = findings.find((finding) => finding.id === "PARSE_FAILURE_AST");
      expect(failure).toBeDefined();
      expect(failure?.metadata?.["error"]).toMatch(/.+/);
      expect(failure?.metadata?.["error"]).not.toBe("[object Object]");
      expect(failure?.metadata?.["error"]).not.toBe("Unknown parser error");
    });

    it("handles empty files", () => {
      const contents = makeContents({ "empty.js": "" });

      const findings = checkAST(contents).findings;
      expect(findings).toHaveLength(0);
    });
  });

  // ============================================================================
  // OBFUSCATION INDICATORS
  // ============================================================================

  describe("obfuscation indicators", () => {
    it("includes additional info when obfuscation is detected", () => {
      const content = `
        var _0x4a2b = function() { return 'test'; };
        eval(_0x4a2b());
      `;
      const contents = makeContents({ "obfuscated.js": content });

      const findings = checkAST(contents).findings;
      const finding = findings.find((f) => f.id === "AST_EVAL_DYNAMIC");

      expect(finding?.metadata?.["additionalInfo"]).toContain("obfuscation");
    });
  });
});
