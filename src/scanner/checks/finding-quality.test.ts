import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { scanExtension } from "#internal/scanner/index.js";

it("retains actionable evidence on a real finding and its source observation", async () => {
  const root = await mkdtemp(join(tmpdir(), "vsix-finding-quality-"));
  try {
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0" }),
    );
    await writeFile(join(root, "main.js"), "// source\neval(payload);\n");
    const result = await scanExtension(root, {
      output: "json",
      severity: "low",
      modules: ["ast"],
      intel: "none",
    });
    expect(result.metadata.coverage.degraded).toBe(false);
    expect(result.findings).toMatchObject([
      {
        id: "AST_EVAL_DYNAMIC",
        severity: "high",
        category: "ast",
        location: { file: "main.js", line: 2, column: 1 },
        metadata: {
          codeSnippet: "eval(payload);",
          legitimateUses: ["REPL implementations", "Dynamic expression evaluators"],
          redFlags: ["Argument is decoded/decrypted value", "Combined with obfuscation"],
        },
      },
    ]);
    expect(result.observations).toMatchObject([
      {
        kind: "code-execution",
        api: "global.eval",
        evidence: "call",
        arguments: [{ kind: "unresolved", expression: "payload" }],
        location: { file: "main.js", line: 2, column: 1, endLine: 2, endColumn: 14 },
      },
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
