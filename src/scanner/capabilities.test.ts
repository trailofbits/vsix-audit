import { describe, expect, it } from "vitest";
import { extractCapabilities, type Capabilities } from "#internal/scanner/capabilities.js";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { checkWallets } from "#internal/scanner/checks/ioc.js";
import { makeContents } from "#internal/test-support/fixtures.js";

function capabilities(source: string): Capabilities {
  const result = checkAST(makeContents({ "main.js": source }));
  return extractCapabilities({
    findings: result.findings,
    observations: result.observations ?? [],
  });
}

describe("capability evidence", () => {
  it.each([
    ['fetch("https://example.invalid");', "network", "global.fetch"],
    ['require("fs").readFileSync("/tmp/cache");', "fileAccess", "fs.readFileSync"],
    ["new Function(payload);", "execution", "global.Function"],
    ['require("keytar").getPassword("service", "account");', "credentials", "keytar.getPassword"],
  ] as const)("summarizes actual source observations: %s", (source, capability, api) => {
    const result = capabilities(source)[capability];
    expect(result.detected).toBe(true);
    expect(result.summary.join(" ")).toContain(api);
    expect(result.evidence).toContainEqual(
      expect.objectContaining({
        file: "main.js",
        line: 1,
        column: expect.any(Number) as unknown,
        matched: expect.stringContaining("(") as unknown,
      }),
    );
  });

  it.each([false, true])(
    "keeps public wallet references separate from credential access: %s",
    (known) => {
      const wallet = "0x1234567890abcdef1234567890abcdef12345678";
      const findings = checkWallets(
        makeContents({ "main.js": `const address = "${wallet}";` }),
        new Set(known ? [wallet] : []),
      );
      expect(findings).toHaveLength(1);
      expect(extractCapabilities({ findings, observations: [] }).credentials).toEqual({
        detected: false,
        summary: [],
        evidence: [],
        indicators: [],
      });
    },
  );

  it("does not discard evidence after the tenth occurrence", () => {
    const result = capabilities(
      Array.from({ length: 12 }, (_, n) => `eval(payload${n});`).join("\n"),
    );
    expect(result.execution.evidence).toHaveLength(12);
    expect(result.execution.evidence.at(-1)).toMatchObject({
      line: 12,
      matched: "eval(payload11)",
    });
  });
});
