import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { brotliDecompressSync } from "node:zlib";
import { describe, expect, it, vi } from "vitest";
import { findLtrRangeOffsets } from "#internal/scanner/checks/bidi-ranges.js";
import { checkObfuscation } from "#internal/scanner/checks/obfuscation.js";
import type { Finding, VsixContents } from "#internal/scanner/types.js";

const LRE = "\u202a";
const KATEX_BYTES = brotliDecompressSync(
  readFileSync(new URL("./fixtures/markdown-all-in-one-3.6.3-main.js.br", import.meta.url)),
);
const KATEX_SOURCE = KATEX_BYTES.toString("utf8");

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

const ranges = [
  `[${LRE}-\uffff]`,
  `[a-${LRE}]`,
  `[^${LRE}-\uffff]`,
  `[!-\\[\\]-\u2027${LRE}-\ud7ff\uf900-\uffff]`,
  `[a-${LRE}][${LRE}-\uffff]`,
  `[\\u2020-${LRE}]`,
];

describe("hash-pinned KaTeX range data", () => {
  it("verifies the fixture's independently recorded source hash and size", () => {
    expect(Buffer.byteLength(KATEX_SOURCE)).toBe(1_533_214);
    expect(createHash("sha256").update(KATEX_SOURCE).digest("hex")).toBe(
      "9e351182a9d98bf1b3ba0b4bf5a08658e15147d4bd55596e8bf30b549145151b",
    );
  });

  it("exempts only the known occurrence in the exact source", () => {
    const occurrences = Array.from(KATEX_SOURCE.matchAll(/\u202a/g), (match) => match.index);
    expect(occurrences).toEqual([383_378]);
    expect(findLtrRangeOffsets(KATEX_BYTES, "dist/node/main.js")).toEqual(new Set(occurrences));
    expect(directionalFindings(KATEX_SOURCE, "dist/node/main.js")).toEqual([]);
  });

  it("recognizes identical source under a different JavaScript filename", () => {
    expect(findLtrRangeOffsets(KATEX_BYTES, "copy.js")).toEqual(new Set([383_378]));
  });

  it.each([
    (source: string): string => "// changed\n" + source,
    (source: string): string => source + "\n// changed",
    (source: string): string => source.replace("var e,t,n,r", "var e,t,n,s"),
  ])("retains the alert after any change to the pinned source", (change) => {
    const source = change(KATEX_SOURCE);
    expect(source).not.toBe(KATEX_SOURCE);
    expect(directionalFindings(source, "dist/node/main.js")).toHaveLength(1);
  });

  it("rejects a forged filename and occurrence offset", () => {
    const prefix = 'const pattern = "[a-';
    const source = " ".repeat(383_378 - prefix.length) + prefix + LRE + ']";';
    expect(source.indexOf(LRE)).toBe(383_378);
    expect(directionalFindings(source, "dist/node/main.js")).toHaveLength(1);
  });

  it("invalidates every source exception when more controls are appended", () => {
    const source = KATEX_SOURCE + `\nconst hidden = "${LRE.repeat(6)}"; eval(hidden);`;
    expect(findLtrRangeOffsets(Buffer.from(source), "dist/node/main.js")).toEqual(new Set());
    expect(
      directionalFindings(source).find((finding) => finding.id === "BIDI_OVERRIDE"),
    ).toMatchObject({ severity: "critical", metadata: { matchCount: 7 } });
  });
});

describe("regex literals", () => {
  it.each(ranges)("accepts a literal range endpoint: %j", (pattern) => {
    expect(directionalFindings(`const pattern = /${pattern}/u;`)).toEqual([]);
  });

  it.each([
    ["", `[\\_-${LRE}]`],
    ["", `[\\${LRE}-\uffff]`],
    ["v", `[[a-${LRE}]]`],
    ["v", `[[abc]z-${LRE}]`],
    ["v", `[[a-${LRE}]&&[\\s\\S]]`],
    ["v", `[\\q{ab}[a-${LRE}]]`],
  ])("uses the literal's declared /%s mode: %j", (flags, pattern) => {
    expect(() => new RegExp(pattern, flags)).not.toThrow();
    expect(directionalFindings(`const pattern = /${pattern}/${flags};`)).toEqual([]);
  });

  it.each([
    `const pattern = /[${LRE}]/u;`,
    `const pattern = /[${LRE}\\-a]/u;`,
    `const pattern = /[a--${LRE}]/v;`,
    `const pattern = /[\\q{a\\-${LRE}}]/v;`,
    `const pattern = /[z-a${LRE}]/u;`,
  ])("retains controls outside valid range endpoints: %j", (source) => {
    expect(directionalFindings(source)).toHaveLength(1);
  });

  it("does not depend on the global RegExp binding", () => {
    expect(
      directionalFindings(`globalThis.RegExp = consume; const pattern = /[a-${LRE}]/u;`),
    ).toEqual([]);
  });

  it("retains a separate control after astral characters", () => {
    const source = `const emoji = "💡"; const pattern = /[a-${LRE}]/u;\n// ${LRE}`;
    expect(directionalFindings(source)).toMatchObject([
      { location: { line: 2, column: 4 }, metadata: { matchCount: 1 } },
    ]);
  });
});

describe("other strings and source", () => {
  it.each(ranges)("retains a constructor-string range: %j", (pattern) => {
    expect(
      directionalFindings(`const p = ${JSON.stringify(pattern)}; new RegExp(p);`),
    ).toHaveLength(1);
  });

  it.each([
    "",
    "globalThis.RegExp = consume;",
    'globalThis["RegExp"] = consume;',
    "let root = globalThis; root.RegExp = consume;",
    "const [root] = [globalThis]; root.RegExp = consume;",
    "const root = true ? globalThis : {}; root.RegExp = consume;",
    "globalThis.globalThis.RegExp = consume;",
    "function getRoot() { return globalThis; } getRoot().RegExp = consume;",
    "with ({RegExp: consume}) {}",
  ])("retains alerts regardless of constructor resolution: %j", (prefix) => {
    const pattern = JSON.stringify(Array.from({ length: 6 }, () => `[a-${LRE}]`).join(""));
    const source = `${prefix} RegExp(${pattern}); eval(payload);`;
    expect(directionalFindings(source).map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["BIDI_OVERRIDE", "INVISIBLE_CODE_EXECUTION"]),
    );
  });

  it.each(["js", "mjs", "cjs", "ts", "jsx", "tsx", "TS", "py", "json", "md", "txt"])(
    "retains untrusted strings in %s files",
    (extension) => {
      expect(
        directionalFindings(`const pattern = "[a-${LRE}]";`, `source.${extension}`),
      ).toHaveLength(1);
    },
  );

  it("retains controls in typed constructor expressions", () => {
    const source =
      `(globalThis as typeof globalThis).RegExp = consume;` +
      `(RegExp as typeof RegExp)("[a-${LRE}]" as string);`;
    expect(directionalFindings(source, "source.ts")).toHaveLength(1);
  });

  it.each([
    `// [a-${LRE}]`,
    `/* [${LRE}-\uffff] */`,
    `const text = "message${LRE}hidden";`,
    `const pattern = \`[a-${LRE}]\`;`,
    `const pattern = /[a-${LRE}]/u; const = ;`,
    `const pattern = /[a-${LRE}]/u; let duplicate; let duplicate;`,
  ])("retains controls in comments, text, or invalid programs: %j", (source) => {
    expect(directionalFindings(source)).toHaveLength(1);
  });

  it.each(["\u202b", "\u202c", "\u202d", "\u202e"])(
    "retains other directional controls: %j",
    (control) => {
      expect(directionalFindings(`const pattern = /[${control}-\uffff]/u;`)).toHaveLength(1);
    },
  );

  it("retains alerts and reports a traversal failure", () => {
    const warning = vi.spyOn(process, "emitWarning").mockImplementation(() => {});
    try {
      const expression = Array.from({ length: 20_000 }, () => "1").join("+");
      expect(directionalFindings(`const value = ${expression}; // ${LRE}`)).toHaveLength(1);
      expect(warning).toHaveBeenCalledWith(
        expect.stringContaining('BIDI range analysis failed for "extension.js"'),
        { code: "BIDI_RANGE_ANALYSIS_FAILED" },
      );
    } finally {
      warning.mockRestore();
    }
  });
});
