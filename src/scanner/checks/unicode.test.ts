import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest } from "../types.js";
import { checkUnicode } from "./unicode.js";

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

describe("checkUnicode", () => {
  describe("zero-width characters", () => {
    it("detects zero-width space characters (U+200B)", () => {
      // 3+ occurrences needed
      const content = "const x\u200B = 'a\u200Bb\u200Bc';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "ZERO_WIDTH_CHARS")).toBe(true);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });

    it("detects zero-width joiner (U+200D)", () => {
      const content = "const x\u200D = 'a\u200Db\u200Dc';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "ZERO_WIDTH_CHARS")).toBe(true);
    });

    it("ignores files with only 1-2 zero-width chars", () => {
      const content = "const x\u200B = 'a\u200Bb';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);
      const zeroWidthFinding = findings.find((f) => f.id === "ZERO_WIDTH_CHARS");

      expect(zeroWidthFinding).toBeUndefined();
    });
  });

  describe("variation selectors (GlassWorm technique)", () => {
    it("detects variation selectors (U+FE00-FE0F)", () => {
      // Even one variation selector is suspicious in code
      const content = "const x\uFE01 = 'test';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      expect(findings.some((f) => f.severity === "critical")).toBe(true);
    });

    it("detects multiple variation selectors", () => {
      const content = "a\uFE00b\uFE01c\uFE02d\uFE0F";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      const finding = findings.find((f) => f.id === "VARIATION_SELECTOR");
      expect(finding?.metadata?.["matchCount"]).toBe(4);
    });
  });

  describe("bidirectional overrides (Trojan Source)", () => {
    it("detects left-to-right override (U+202D)", () => {
      const content = "const admin\u202D = true;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
      expect(findings.some((f) => f.severity === "critical")).toBe(true);
    });

    it("detects right-to-left override (U+202E)", () => {
      const content = "const admin\u202E = true;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
    });
  });

  describe("Unicode ASCII escapes", () => {
    it("detects excessive Unicode escapes for ASCII", () => {
      // Using \\u00XX for normal printable ASCII is suspicious
      const content = "const x = '\\u0068\\u0065\\u006c\\u006c\\u006f\\u0077';"; // "hellow"
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "UNICODE_ASCII_ESCAPE")).toBe(true);
      expect(findings.some((f) => f.severity === "medium")).toBe(true);
    });

    it("ignores files with few Unicode escapes", () => {
      const content = "const x = '\\u0068\\u0065';"; // Only 2 escapes
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);
      const escapeFinding = findings.find((f) => f.id === "UNICODE_ASCII_ESCAPE");

      expect(escapeFinding).toBeUndefined();
    });
  });

  describe("Cyrillic homoglyphs", () => {
    it("detects Cyrillic 'а' (U+0430) that looks like Latin 'a'", () => {
      const content = "const \u0430dmin = true;"; // Cyrillic а
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(true);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });

    it("detects Cyrillic 'е' (U+0435) that looks like Latin 'e'", () => {
      const content = "const s\u0435cret = 'password';"; // Cyrillic е
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(true);
    });

    it("ignores Cyrillic in markdown files", () => {
      const content = "# Hello \u0430nd welcome"; // Cyrillic а in markdown
      const contents = makeContents({ "README.md": content });

      const findings = checkUnicode(contents);
      const cyrillicFinding = findings.find((f) => f.id === "CYRILLIC_HOMOGLYPH");

      expect(cyrillicFinding).toBeUndefined();
    });
  });

  describe("invisible characters near code execution", () => {
    it("flags invisible chars in file with eval()", () => {
      // File has both: a normal eval() call and invisible chars elsewhere
      const content = "const payload\uFE01 = 'data';\neval(payload);";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      // Should have both VARIATION_SELECTOR and INVISIBLE_CODE_EXECUTION
      expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("flags invisible chars in file with Function()", () => {
      const content = "const x\uFE02 = 1;\nnew Function('return x')();";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("flags invisible chars in file with child_process", () => {
      const content = "require('child_process').exec('ls');\nconst hidden\uFE03 = 1;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("does NOT flag invisible chars without execution context", () => {
      const content = "const x\uFE01 = 'test';"; // variation selector but no eval/exec
      const contents = makeContents({ "extension.js": content });

      const findings = checkUnicode(contents);

      // Should have VARIATION_SELECTOR but NOT INVISIBLE_CODE_EXECUTION
      expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(false);
    });
  });

  describe("file filtering", () => {
    it("scans JavaScript files", () => {
      const content = "const x\uFE01 = 1;";
      const contents = makeContents({ "test.js": content });

      const findings = checkUnicode(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans TypeScript files", () => {
      const content = "const x\uFE01: number = 1;";
      const contents = makeContents({ "test.ts": content });

      const findings = checkUnicode(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans JSON files", () => {
      const content = '{"key\uFE01": "value"}';
      const contents = makeContents({ "test.json": content });

      const findings = checkUnicode(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("ignores binary files", () => {
      const content = "\uFE01\uFE02\uFE03";
      const contents = makeContents({ "test.png": content });

      const findings = checkUnicode(contents);
      expect(findings).toHaveLength(0);
    });
  });

  describe("metadata", () => {
    it("includes match count in metadata", () => {
      const content = "a\uFE00b\uFE01c\uFE02";
      const contents = makeContents({ "test.js": content });

      const findings = checkUnicode(contents);
      const finding = findings.find((f) => f.id === "VARIATION_SELECTOR");

      expect(finding?.metadata?.["matchCount"]).toBe(3);
    });

    it("includes code points in metadata", () => {
      const content = "a\uFE00b";
      const contents = makeContents({ "test.js": content });

      const findings = checkUnicode(contents);
      const finding = findings.find((f) => f.id === "VARIATION_SELECTOR");
      const codePoints = finding?.metadata?.["codePoints"] as string[] | undefined;

      expect(codePoints).toBeDefined();
      expect(codePoints?.some((cp) => cp.includes("FE00"))).toBe(true);
    });

    it("includes line number in location", () => {
      const content = "line1\nline2\nconst x\uFE01 = 1;";
      const contents = makeContents({ "test.js": content });

      const findings = checkUnicode(contents);
      const finding = findings.find((f) => f.id === "VARIATION_SELECTOR");

      expect(finding?.location?.line).toBe(3);
    });
  });
});
