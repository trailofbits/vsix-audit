import { describe, expect, it, vi } from "vitest";
import { checkObfuscation } from "#internal/scanner/checks/obfuscation.js";
import type { Finding, VsixContents } from "#internal/scanner/types.js";

const LRE = "\u202a";

function directionalFindings(source: string, filename = "extension.js"): Finding[] {
  const contents: VsixContents = {
    manifest: { name: "bidi-fixture", publisher: "test", version: "1.0.0" },
    files: new Map([[filename, Buffer.from(source)]]),
    basePath: "/fixture",
  };
  return checkObfuscation(contents).filter((finding) =>
    ["BIDI_OVERRIDE", "INVISIBLE_CODE_EXECUTION"].includes(finding.id),
  );
}

const safePatterns = [
  `[${LRE}-\uffff]`,
  `[a-${LRE}]`,
  `[^${LRE}-\uffff]`,
  `[!-\\[\\]-\u2027${LRE}-\ud7ff\uf900-\uffff]`,
  `[a-${LRE}][${LRE}-\uffff]`,
  `[\\u2020-${LRE}]`,
];

describe("BIDI controls in regex data", () => {
  it.each(safePatterns)("accepts an LRE range in a string literal: %j", (pattern) => {
    expect(directionalFindings(`const pattern = ${JSON.stringify(pattern)} + suffix;`)).toEqual([]);
  });

  it.each(["js", "mjs", "cjs", "ts", "jsx", "tsx"])(
    "accepts range data in %s source",
    (extension) => {
      const source = `const pattern = "[${LRE}-\uffff]";`;
      expect(directionalFindings(source, `extension.${extension}`)).toEqual([]);
    },
  );

  it.each(["ts", "TS", "tsx", "TSX"])("parses type syntax in %s files", (extension) => {
    const source = `const pattern: string = "[${LRE}-\uffff]";`;
    expect(directionalFindings(source, `extension.${extension}`)).toEqual([]);
  });

  it("accepts range data in a regex literal", () => {
    expect(directionalFindings(`const pattern = /[${LRE}-\uffff]/u;`)).toEqual([]);
  });

  it("keeps the correct source position after astral characters and escapes", () => {
    const source = `const emoji = "💡"; const pattern = "\\n[${LRE}-\uffff]";\n// ${LRE} alert`;
    const findings = directionalFindings(source);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "critical",
      location: { line: 2, column: 4 },
      metadata: { matchCount: 1 },
    });
  });
});

describe("BIDI controls in declared regex modes", () => {
  it.each([`[\\_-${LRE}]`, `[\\a-${LRE}]`, `[\\${LRE}-\uffff]`])(
    "accepts a legacy range stored in a string: %j",
    (pattern) => {
      expect(() => new RegExp(pattern)).not.toThrow();
      const source = `const pattern = ${JSON.stringify(pattern)}; new RegExp(pattern);`;
      expect(directionalFindings(source)).toEqual([]);
    },
  );

  it("keeps a legacy class escape followed by a literal hyphen reportable", () => {
    const pattern = `[\\s-${LRE}]`;
    expect(() => new RegExp(pattern)).not.toThrow();
    expect(directionalFindings(`const pattern = ${JSON.stringify(pattern)};`)).toHaveLength(1);
  });

  it.each([
    ["", `[\\_-${LRE}]`],
    ["", `[\\${LRE}-\uffff]`],
    ["u", `[a-${LRE}]`],
    ["v", `[[a-${LRE}]]`],
    ["v", `[[a-${LRE}]&&[\\s\\S]]`],
    ["v", `[\\q{ab}[a-${LRE}]]`],
  ])("accepts an actual range endpoint in /%s mode: %j", (flags, pattern) => {
    expect(() => new RegExp(pattern, flags)).not.toThrow();
    expect(directionalFindings(`const pattern = /${pattern}/${flags};`)).toEqual([]);
  });

  it.each([`[a--${LRE}]`, `[${LRE}--a]`, `[\\q{a\\-${LRE}}]`])(
    "retains alerts for Unicode set operands and string members: %j",
    (pattern) => {
      expect(() => new RegExp(pattern, "v")).not.toThrow();
      expect(directionalFindings(`const pattern = /${pattern}/v;`)).toHaveLength(1);
    },
  );

  it("retains alerts and reports a diagnostic when traversal exceeds its stack limit", () => {
    const warning = vi.spyOn(process, "emitWarning").mockImplementation(() => {});
    try {
      const expression = Array.from({ length: 20_000 }, () => "1").join("+");
      const source = `const value = ${expression}; // ${LRE}`;
      expect(directionalFindings(source)).toHaveLength(1);
      expect(warning).toHaveBeenCalledWith(
        expect.stringContaining('BIDI range analysis failed for "extension.js"'),
        { code: "BIDI_RANGE_ANALYSIS_FAILED" },
      );
    } finally {
      warning.mockRestore();
    }
  });
});

describe("BIDI controls outside range data", () => {
  it.each([
    `// [a-${LRE}]`,
    `/* [${LRE}-\uffff] */`,
    `const text = "message${LRE}hidden";`,
    `const pattern = "[${LRE}]";`,
    `const pattern = "[-${LRE}]";`,
    `const pattern = "[^-${LRE}]";`,
    `const pattern = "[${LRE}-]";`,
    `const pattern = ${JSON.stringify(`[a\\-${LRE}]`)};`,
    `const pattern = ${JSON.stringify(`\\[a-${LRE}]`)};`,
    `const pattern = "[${LRE}-\uffff";`,
    `const pattern = "[z-a${LRE}-\uffff]";`,
    `const pattern = /[z-a${LRE}]/u;`,
    `const pattern = "[${LRE}-\uffff]"; const = ;`,
    `const pattern = "[${LRE}-\uffff]"; let duplicate; let duplicate;`,
    `const pattern = \`[${LRE}-\uffff]\`;`,
    `const pattern = "\\u202a[${LRE}-\uffff]";`,
  ])("retains an alert outside an unambiguous parsed range: %j", (source) => {
    expect(directionalFindings(source)).toHaveLength(1);
  });

  it.each(["py", "json", "md", "txt"])("retains alerts in %s files", (extension) => {
    expect(directionalFindings(`"[${LRE}-\uffff]"`, `source.${extension}`)).toHaveLength(1);
  });

  it.each(["\u202b", "\u202c", "\u202d", "\u202e"])(
    "retains other directional controls inside range data: %j",
    (control) => {
      expect(directionalFindings(`const pattern = "[${control}-\uffff]";`)).toHaveLength(1);
    },
  );

  it.each([
    `const pattern = ${JSON.stringify(`[${LRE}\\-a]`)};`,
    `const pattern = /[${LRE}\\-a]/u;`,
  ])("retains an LRE followed by an escaped hyphen: %j", (source) => {
    expect(directionalFindings(source)).toHaveLength(1);
  });

  it("retains escaped hyphens near execution", () => {
    const patterns = JSON.stringify(Array.from({ length: 6 }, () => `[${LRE}\\-a]`));
    const source = `const patterns = ${patterns}; new Function(patterns.join(''));`;
    expect(directionalFindings(source).map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["BIDI_OVERRIDE", "INVISIBLE_CODE_EXECUTION"]),
    );
  });

  it("retains Trojan Source controls alongside safe range data", () => {
    const source = `const pattern = "[${LRE}-\uffff]";\n/* \u202e hidden \u202c */`;
    expect(directionalFindings(source)[0]).toMatchObject({
      severity: "critical",
      location: { line: 2 },
      metadata: { matchCount: 2 },
    });
  });

  it("does not count safe range data as invisible execution", () => {
    const source =
      `const patterns = ${JSON.stringify(Array.from({ length: 6 }, () => `[${LRE}-\uffff]`))};` +
      "new Function(patterns.join(''));";
    expect(directionalFindings(source)).toEqual([]);
  });

  it("keeps ordinary embeddings near execution visible", () => {
    const source = `const data = "${LRE.repeat(6)}"; eval(data);`;
    expect(directionalFindings(source).map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["BIDI_OVERRIDE", "INVISIBLE_CODE_EXECUTION"]),
    );
  });

  it.each(["'", '"'])("handles generated range boundaries with %s quoting", (quote) => {
    for (const endpoint of [0x21, 0x7f, 0xff, 0x2029, 0x202b, 0xd7ff, 0xffff]) {
      const escape = `\\u${endpoint.toString(16).padStart(4, "0")}`;
      const range = endpoint < 0x202a ? `${escape}-${LRE}` : `${LRE}-${escape}`;
      expect(directionalFindings(`const pattern = ${quote}[${range}]${quote};`)).toEqual([]);
    }
  });
});
