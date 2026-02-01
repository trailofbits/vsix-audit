import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest } from "../types.js";
import { checkObfuscation } from "./obfuscation.js";

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

describe("checkObfuscation", () => {
  // ============================================================================
  // ENTROPY DETECTION
  // ============================================================================

  describe("entropy detection", () => {
    it("detects high entropy regions", () => {
      // Generate high-entropy string using full alphanumeric charset (62 chars)
      // Each char used ~equally = entropy near log2(62) ≈ 5.95 bits/char
      // Threshold is 5.5, so this will trigger detection
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let highEntropy = "";
      for (let i = 0; i < 300; i++) {
        highEntropy += chars[i % chars.length];
      }
      const content = `const data = "${highEntropy}";`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "OBFUSCATION_HIGH_ENTROPY")).toBe(true);
    });

    it("ignores normal code with low entropy", () => {
      const content = `
        function hello() {
          console.log("Hello, World!");
          return true;
        }
      `;
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "OBFUSCATION_HIGH_ENTROPY")).toBe(false);
    });
  });

  // ============================================================================
  // UNICODE HIDING DETECTION
  // ============================================================================

  describe("Unicode - zero-width characters", () => {
    it("detects zero-width space characters (U+200B)", () => {
      // 3+ occurrences needed
      const content = "const x\u200B = 'a\u200Bb\u200Bc';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "ZERO_WIDTH_CHARS")).toBe(true);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });

    it("detects zero-width joiner (U+200D)", () => {
      const content = "const x\u200D = 'a\u200Db\u200Dc';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "ZERO_WIDTH_CHARS")).toBe(true);
    });

    it("ignores files with only 1-2 zero-width chars", () => {
      const content = "const x\u200B = 'a\u200Bb';";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);
      const zeroWidthFinding = findings.find((f) => f.id === "ZERO_WIDTH_CHARS");

      expect(zeroWidthFinding).toBeUndefined();
    });
  });

  describe("Unicode - variation selectors (GlassWorm technique)", () => {
    it("detects variation selectors (U+FE00-FE0F) when >= 50 present", () => {
      // Implementation requires 50+ variation selectors (GlassWorm uses hundreds)
      // Normal emoji use has far fewer variation selectors
      const variations = Array(55).fill("\uFE0F").join("x");
      const content = `const payload = "${variations}";`;
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      expect(findings.some((f) => f.severity === "critical")).toBe(true);
    });

    it("ignores few variation selectors (normal for emoji)", () => {
      // Less than 50 variation selectors should be ignored (normal emoji use)
      const content = "a\uFE00b\uFE01c\uFE02d\uFE0F";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.find((f) => f.id === "VARIATION_SELECTOR")).toBeUndefined();
    });
  });

  describe("Unicode - bidirectional overrides (Trojan Source)", () => {
    it("detects left-to-right override (U+202D)", () => {
      const content = "const admin\u202D = true;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
      expect(findings.some((f) => f.severity === "critical")).toBe(true);
    });

    it("detects right-to-left override (U+202E)", () => {
      const content = "const admin\u202E = true;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
    });
  });

  describe("Unicode - ASCII escapes", () => {
    it("detects excessive Unicode escapes for ASCII", () => {
      // Using \\u00XX for normal printable ASCII is suspicious
      const content = "const x = '\\u0068\\u0065\\u006c\\u006c\\u006f\\u0077';"; // "hellow"
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "UNICODE_ASCII_ESCAPE")).toBe(true);
      expect(findings.some((f) => f.severity === "medium")).toBe(true);
    });

    it("ignores files with few Unicode escapes", () => {
      const content = "const x = '\\u0068\\u0065';"; // Only 2 escapes
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);
      const escapeFinding = findings.find((f) => f.id === "UNICODE_ASCII_ESCAPE");

      expect(escapeFinding).toBeUndefined();
    });
  });

  describe("Unicode - Cyrillic homoglyphs", () => {
    it("detects Cyrillic 'а' (U+0430) that looks like Latin 'a'", () => {
      const content = "const \u0430dmin = true;"; // Cyrillic а
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(true);
      expect(findings.some((f) => f.severity === "high")).toBe(true);
    });

    it("detects Cyrillic 'е' (U+0435) that looks like Latin 'e'", () => {
      const content = "const s\u0435cret = 'password';"; // Cyrillic е
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings).toHaveLength(1);
      expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(true);
    });

    it("ignores Cyrillic in markdown files", () => {
      const content = "# Hello \u0430nd welcome"; // Cyrillic а in markdown
      const contents = makeContents({ "README.md": content });

      const findings = checkObfuscation(contents);
      const cyrillicFinding = findings.find((f) => f.id === "CYRILLIC_HOMOGLYPH");

      expect(cyrillicFinding).toBeUndefined();
    });
  });

  describe("Unicode - invisible characters near code execution", () => {
    it("flags many invisible chars in file with eval()", () => {
      // Implementation requires 5+ invisible chars near execution patterns
      const content = "const payload\uFE01\uFE02\uFE03\uFE04\uFE05 = 'data';\neval(payload);";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("flags many invisible chars in file with Function()", () => {
      const content = "const x\uFE01\uFE02\uFE03\uFE04\uFE05 = 1;\nnew Function('return x')();";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("flags many invisible chars in file with child_process", () => {
      const content =
        "require('child_process').exec('ls');\nconst hidden\uFE01\uFE02\uFE03\uFE04\uFE05 = 1;";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(true);
    });

    it("does NOT flag few invisible chars even with execution context", () => {
      // Single invisible char isn't enough - needs 5+
      const content = "const x\uFE01 = 1;\neval(x);";
      const contents = makeContents({ "extension.js": content });

      const findings = checkObfuscation(contents);

      expect(findings.some((f) => f.id === "INVISIBLE_CODE_EXECUTION")).toBe(false);
    });
  });

  describe("file filtering", () => {
    it("scans JavaScript files", () => {
      // Use bidi override which triggers with just 1 occurrence
      const content = "const admin\u202E = true;";
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans TypeScript files", () => {
      const content = "const admin\u202E: boolean = true;";
      const contents = makeContents({ "test.ts": content });

      const findings = checkObfuscation(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans JSON files for unicode issues", () => {
      const content = '{"key\u202E": "value"}';
      const contents = makeContents({ "test.json": content });

      const findings = checkObfuscation(contents);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("ignores binary files", () => {
      // Even critical patterns should be ignored in binary files
      const content = "\u202E\u202D\u202C";
      const contents = makeContents({ "test.png": content });

      const findings = checkObfuscation(contents);
      expect(findings).toHaveLength(0);
    });
  });

  describe("metadata", () => {
    it("includes match count in metadata for unicode findings", () => {
      // Use BIDI_OVERRIDE which triggers with 1+ occurrences
      const content = "a\u202Db\u202Ec\u202D";
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "BIDI_OVERRIDE");

      expect(finding?.metadata?.["matchCount"]).toBe(3);
    });

    it("includes code points in metadata for unicode findings", () => {
      const content = "const admin\u202E = true;";
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "BIDI_OVERRIDE");
      const codePoints = finding?.metadata?.["codePoints"] as string[] | undefined;

      expect(codePoints).toBeDefined();
      expect(codePoints?.some((cp) => cp.includes("202E"))).toBe(true);
    });

    it("includes line number in location", () => {
      const content = "line1\nline2\nconst admin\u202E = true;";
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "BIDI_OVERRIDE");

      expect(finding?.location?.line).toBe(3);
    });

    it("includes obfuscation score for entropy findings", () => {
      // Use full alphanumeric charset for high entropy (log2(62) ≈ 5.95 bits/char)
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let highEntropy = "";
      for (let i = 0; i < 300; i++) {
        highEntropy += chars[i % chars.length];
      }
      const content = `const data = "${highEntropy}";`;
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "OBFUSCATION_HIGH_ENTROPY");

      expect(finding?.metadata?.["obfuscationScore"]).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // FALSE POSITIVE EXCLUSIONS
  // ============================================================================

  describe("false positive exclusions", () => {
    describe("node_modules exclusions", () => {
      it("skips high entropy detection in node_modules", () => {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let highEntropy = "";
        for (let i = 0; i < 300; i++) {
          highEntropy += chars[i % chars.length];
        }
        const content = `const data = "${highEntropy}";`;
        const contents = makeContents({
          "node_modules/iconv-lite/encodings/tables/cp437.js": content,
        });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "OBFUSCATION_HIGH_ENTROPY")).toBe(false);
      });

      it("skips zero-width chars in node_modules", () => {
        const content = "const x\u200B = 'a\u200Bb\u200Bc';"; // 3 zero-width spaces
        const contents = makeContents({ "node_modules/moment/locale/ku.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "ZERO_WIDTH_CHARS")).toBe(false);
      });

      it("skips Cyrillic homoglyphs in node_modules", () => {
        const content = "const \u0430dmin = true;"; // Cyrillic а
        const contents = makeContents({ "node_modules/iconv-lite/lib/extend-node.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(false);
      });

      it("still detects BIDI_OVERRIDE in node_modules (critical)", () => {
        const content = "const admin\u202E = true;";
        const contents = makeContents({ "node_modules/suspicious-package/index.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
      });
    });

    describe("emoji and entity file exclusions", () => {
      it("skips variation selectors in emoji.json", () => {
        // 50+ variation selectors would normally trigger
        const variations = "\uFE0F".repeat(60);
        const content = `{"emoji": "👍${variations}"}`;
        const contents = makeContents({ "extension/out/emoji.json": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(false);
      });

      it("skips variation selectors in entities.json", () => {
        const variations = "\uFE0F".repeat(60);
        const content = `{"entity": "test${variations}"}`;
        const contents = makeContents({ "extension/out/entities.json": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(false);
      });

      it("skips variation selectors in README.md", () => {
        const variations = "\uFE0F".repeat(60);
        const content = `# README\nEmoji test: ${variations}`;
        const contents = makeContents({ "extension/README.md": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(false);
      });

      it("still detects variation selectors in suspicious JS files", () => {
        // 50+ variation selectors in a non-emoji file
        const variations = Array(55).fill("\uFE00").join("x");
        const content = `const payload = "${variations}"; eval(payload);`;
        const contents = makeContents({ "extension.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      });
    });

    describe("RTL file exclusions", () => {
      it("skips BIDI_OVERRIDE in katex files", () => {
        const content = "const rtl\u202E = true;";
        const contents = makeContents({ "node_modules/katex/dist/katex.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(false);
      });

      it("skips BIDI_OVERRIDE in mermaid files", () => {
        const content = "const rtl\u202E = true;";
        const contents = makeContents({ "node_modules/mermaid/dist/mermaid.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(false);
      });

      it("skips BIDI_OVERRIDE in Hebrew language files", () => {
        const content = "Hebrew text\u202Ehere";
        const contents = makeContents({ "extension/resources/dia_he.txt": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(false);
      });

      it("still detects BIDI_OVERRIDE in regular JS files", () => {
        const content = "const admin\u202E = true;";
        const contents = makeContents({ "extension/src/index.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "BIDI_OVERRIDE")).toBe(true);
      });
    });

    describe("i18n file exclusions", () => {
      it("skips Cyrillic in moment locale files", () => {
        const content = "const \u0430dmin = '\u0435xample';"; // Cyrillic а and е
        const contents = makeContents({ "moment/locale/ru.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(false);
      });

      it("skips Cyrillic in encoding table files", () => {
        const content = "module.exports = { '\u0430': 0x00 };"; // Cyrillic а
        const contents = makeContents({ "encodings/tables/cp866.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "CYRILLIC_HOMOGLYPH")).toBe(false);
      });
    });

    describe("variation selector threshold", () => {
      it("ignores fewer than 50 variation selectors (normal emoji use)", () => {
        // 30 variation selectors - below threshold
        const variations = Array(30).fill("\uFE0F").join("x");
        const content = `const emoji = "${variations}";`;
        const contents = makeContents({ "extension.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(false);
      });

      it("detects 50+ variation selectors (GlassWorm technique)", () => {
        // 55 variation selectors - above threshold
        const variations = Array(55).fill("\uFE0F").join("x");
        const content = `const payload = "${variations}";`;
        const contents = makeContents({ "extension.js": content });

        const findings = checkObfuscation(contents);

        expect(findings.some((f) => f.id === "VARIATION_SELECTOR")).toBe(true);
      });
    });
  });

  describe("category assignment", () => {
    it("assigns obfuscation category to entropy findings", () => {
      // Use full alphanumeric charset for high entropy (log2(62) ≈ 5.95 bits/char)
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let highEntropy = "";
      for (let i = 0; i < 300; i++) {
        highEntropy += chars[i % chars.length];
      }
      const content = `const data = "${highEntropy}";`;
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "OBFUSCATION_HIGH_ENTROPY");

      expect(finding?.category).toBe("obfuscation");
    });

    it("assigns obfuscation category to unicode findings", () => {
      const content = "const admin\u202E = true;";
      const contents = makeContents({ "test.js": content });

      const findings = checkObfuscation(contents);
      const finding = findings.find((f) => f.id === "BIDI_OVERRIDE");

      expect(finding?.category).toBe("obfuscation");
    });
  });
});
