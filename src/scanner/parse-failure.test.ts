import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { scanExtension } from "#internal/scanner/index.js";
import type { VsixContents } from "#internal/scanner/types.js";

const DEEP_SOURCE =
  `eval(beforePayload); const value = ` +
  `${Array.from({ length: 20_000 }, () => "1").join("+\n")}; // \u202a`;
const MANIFEST = { name: "parser-fixture", publisher: "test", version: "1.0.0", main: "main.js" };

describe("AST traversal failures", () => {
  it.each([
    { severity: "low", ids: ["PARSE_FAILURE_AST"], incomplete: [true] },
    { severity: "critical", ids: [], incomplete: [] },
  ] as const)(
    "degrades coverage for recoverable errors at $severity severity",
    async ({ severity, ids, incomplete }) => {
      const directory = await mkdtemp(join(tmpdir(), "vsix-parser-recovery-"));
      try {
        await writeFile(join(directory, "package.json"), JSON.stringify(MANIFEST));
        await writeFile(join(directory, "main.js"), "const missing;");
        const result = await scanExtension(directory, {
          output: "json",
          severity,
          modules: ["ast"],
        });
        expect(result.metadata.coverage.degraded).toBe(true);
        expect(result.metadata.coverage.warnings).toEqual([expect.stringContaining('"main.js"')]);
        expect(result.findings.map((finding) => finding.id)).toEqual(ids);
        expect(result.findings.map((finding) => finding.metadata?.["analysisIncomplete"])).toEqual(
          incomplete,
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  it("preserves a fatal diagnostic after the parser has recovered", async () => {
    const directory = await mkdtemp(join(tmpdir(), "vsix-parser-recovery-"));
    try {
      await writeFile(join(directory, "package.json"), JSON.stringify(MANIFEST));
      await writeFile(join(directory, "main.js"), `const missing;\n${DEEP_SOURCE}`);
      const result = await scanExtension(directory, {
        output: "json",
        severity: "low",
        modules: ["ast"],
      });
      const failures = result.findings.filter((finding) => finding.id === "PARSE_FAILURE_AST");
      expect(failures).toHaveLength(1);
      expect(failures[0]?.metadata?.["analysisIncomplete"]).toBe(true);
      expect(failures[0]?.metadata?.["error"]).toEqual(expect.stringContaining("stack"));
      expect(failures[0]?.metadata?.["recoveryError"]).toEqual(
        expect.stringContaining("initializer"),
      );
      expect(result.metadata.coverage.degraded).toBe(true);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reports incomplete analysis and continues with the following file", () => {
    const contents: VsixContents = {
      manifest: MANIFEST,
      files: new Map([
        ["main.js", Buffer.from(DEEP_SOURCE)],
        ["after.js", Buffer.from("eval(payload);")],
      ]),
      basePath: "/fixture",
    };
    const findings = checkAST(contents).findings;
    const failure = findings.find((finding) => finding.id === "PARSE_FAILURE_AST");
    expect(failure?.location?.file).toBe("main.js");
    expect(failure?.metadata?.["analysisIncomplete"]).toBe(true);
    expect(failure?.metadata?.["error"]).toEqual(expect.stringContaining("stack"));
    const evalFiles = findings
      .filter((finding) => finding.id === "AST_EVAL_DYNAMIC")
      .map((finding) => finding.location?.file);
    expect(evalFiles).toEqual(expect.arrayContaining(["main.js", "after.js"]));
  });

  it.each([
    { severity: "low", expected: ["BIDI_OVERRIDE", "PARSE_FAILURE_AST", "AST_EVAL_DYNAMIC"] },
    { severity: "critical", expected: ["BIDI_OVERRIDE"] },
  ] as const)(
    "retains directional alerts and degraded coverage at $severity",
    async ({ severity, expected }) => {
      const directory = await mkdtemp(join(tmpdir(), "vsix-parser-failure-"));
      const warning = vi.spyOn(process, "emitWarning").mockImplementation(() => {});
      try {
        await writeFile(join(directory, "package.json"), JSON.stringify(MANIFEST));
        await writeFile(join(directory, "main.js"), DEEP_SOURCE);
        await writeFile(join(directory, "z-after.js"), "eval(payload);");
        const result = await scanExtension(directory, {
          output: "json",
          severity,
          modules: ["obfuscation", "ast"],
        });
        expect(result.findings.map((finding) => finding.id)).toEqual(
          expect.arrayContaining(Array.from(expected)),
        );
        expect(result.metadata.coverage.degraded).toBe(true);
        expect(warning).toHaveBeenCalled();
      } finally {
        warning.mockRestore();
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
});
