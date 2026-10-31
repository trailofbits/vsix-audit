import { describe, expect, it } from "vitest";
import { extractCapabilities } from "#internal/scanner/capabilities.js";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { checkWallets } from "#internal/scanner/checks/ioc.js";
import { CAPABILITY_NAMES } from "#internal/scanner/types.js";

describe("explicit finding capabilities", () => {
  it.each([
    [false, "CRYPTO_WALLET_DETECTED"],
    [true, "KNOWN_MALWARE_WALLET"],
  ] as const)("keeps public wallet indicators separate from credential access: %s", (known, id) => {
    const wallet = "0x1234567890abcdef1234567890abcdef12345678";
    const findings = checkWallets(
      {
        manifest: { name: "fixture", version: "1.0.0" },
        basePath: "/fixture",
        files: new Map([["main.js", Buffer.from(`const address = "${wallet}";`)]]),
      },
      new Set(known ? [wallet] : []),
    );
    expect(findings.map((finding) => finding.id)).toContain(id);
    expect(extractCapabilities(findings).credentials.detected).toBe(false);
  });

  it("includes Function construction in execution evidence", () => {
    const result = checkAST({
      manifest: { name: "fixture", version: "1.0.0" },
      basePath: "/fixture",
      files: new Map([["main.js", Buffer.from("new Function(payload);")]]),
    });
    expect(extractCapabilities(result.findings).execution).toMatchObject({
      detected: true,
      evidence: [{ file: "main.js" }],
    });
  });

  it.each(CAPABILITY_NAMES)(
    "uses an explicit %s capability regardless of finding name",
    (capability) => {
      const findings = [
        {
          id: "UNRELATED_NAME",
          title: "Observed behavior",
          description: "Fixture",
          severity: "high" as const,
          category: "fixture",
          capabilities: [capability],
          location: { file: "main.js", line: 3 },
          metadata: { matched: "evidence" },
        },
      ];
      expect(extractCapabilities(findings)[capability]).toEqual({
        detected: true,
        summary: ["Observed behavior"],
        evidence: [{ file: "main.js", line: 3, matched: "evidence" }],
      });
    },
  );

  it("does not infer behavior from incidental words in an identifier", () => {
    expect(
      extractCapabilities([
        {
          id: "NETWORK_EXEC_SSH",
          title: "Fixture",
          description: "Fixture",
          severity: "low",
          category: "fixture",
        },
      ]).execution.detected,
    ).toBe(false);
  });
});
