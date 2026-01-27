/**
 * Tests for finding quality and metadata completeness
 *
 * These tests verify that findings have sufficient context for human/agent triage.
 * Run with: VSIX_AUDIT_INTEGRATION_TESTS=1 npm test -- finding-quality
 */

import { tmpdir } from "node:os";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { downloadExtension } from "../download.js";
import { scanExtension, type Finding, type ScanResult } from "../index.js";

const INTEGRATION_TESTS_ENABLED = process.env["VSIX_AUDIT_INTEGRATION_TESTS"] === "1";

interface TestExtension {
  id: string;
  category: "baseline" | "edge-case";
  expectedPatterns?: string[];
}

const TEST_EXTENSIONS: TestExtension[] = [
  { id: "esbenp.prettier-vscode", category: "baseline" },
  { id: "ms-vscode-remote.remote-ssh", category: "edge-case", expectedPatterns: ["SSH"] },
  { id: "eamodio.gitlens", category: "edge-case", expectedPatterns: ["child_process"] },
];

let workDir: string;
const scanResults = new Map<string, ScanResult>();

describe.skipIf(!INTEGRATION_TESTS_ENABLED)("finding quality (integration)", () => {
  beforeAll(async () => {
    workDir = join(tmpdir(), `vsix-audit-test-${Date.now()}`);
    await mkdir(workDir, { recursive: true });

    // Download and scan all test extensions
    for (const ext of TEST_EXTENSIONS) {
      try {
        const { path } = await downloadExtension(ext.id, { destDir: workDir });
        const result = await scanExtension(path, {
          output: "json",
          severity: "low",
          network: false,
        });
        scanResults.set(ext.id, result);
      } catch (error) {
        console.error(`Failed to scan ${ext.id}:`, error);
      }
    }
  }, 120000); // 2 minute timeout for downloads

  afterAll(async () => {
    if (workDir) {
      await rm(workDir, { recursive: true, force: true });
    }
  });

  describe("metadata completeness", () => {
    it("all findings have required fields", () => {
      for (const [extId, result] of scanResults) {
        for (const finding of result.findings) {
          expect(finding.id, `${extId}: finding missing id`).toBeDefined();
          expect(finding.title, `${extId}: finding missing title`).toBeDefined();
          expect(finding.description, `${extId}: finding missing description`).toBeDefined();
          expect(finding.severity, `${extId}: finding missing severity`).toMatch(
            /^(low|medium|high|critical)$/,
          );
          expect(finding.category, `${extId}: finding missing category`).toBeDefined();
        }
      }
    });

    it("all findings have file location", () => {
      for (const [extId, result] of scanResults) {
        for (const finding of result.findings) {
          expect(
            finding.location?.file,
            `${extId} finding ${finding.id}: missing file location`,
          ).toBeDefined();
        }
      }
    });

    it("descriptions are meaningful (>50 chars)", () => {
      for (const [extId, result] of scanResults) {
        for (const finding of result.findings) {
          expect(
            finding.description.length,
            `${extId} finding ${finding.id}: description too short`,
          ).toBeGreaterThan(50);
        }
      }
    });
  });

  describe("edge case documentation", () => {
    it("remote-ssh findings explain legitimate SSH usage", () => {
      const result = scanResults.get("ms-vscode-remote.remote-ssh");
      if (!result) return;

      const sshFindings = result.findings.filter(
        (f) => f.id.includes("SSH") || f.description.toLowerCase().includes("ssh"),
      );

      for (const finding of sshFindings) {
        const hasContext =
          finding.description.toLowerCase().includes("legitimate") ||
          finding.description.toLowerCase().includes("common") ||
          finding.description.toLowerCase().includes("expected") ||
          finding.description.toLowerCase().includes("remote") ||
          (finding.metadata?.["legitimateUses"] as string[] | undefined)?.length;

        expect(
          hasContext,
          `SSH finding ${finding.id} should mention legitimate uses for SSH extension`,
        ).toBe(true);
      }
    });

    it("gitlens findings explain legitimate git CLI usage", () => {
      const result = scanResults.get("eamodio.gitlens");
      if (!result) return;

      const childProcessFindings = result.findings.filter(
        (f) =>
          f.id.includes("CHILD_PROCESS") ||
          f.id.includes("EXEC") ||
          f.description.toLowerCase().includes("child_process"),
      );

      for (const finding of childProcessFindings) {
        const hasContext =
          finding.description.toLowerCase().includes("git") ||
          finding.description.toLowerCase().includes("cli") ||
          finding.description.toLowerCase().includes("legitimate") ||
          finding.description.toLowerCase().includes("common") ||
          (finding.metadata?.["legitimateUses"] as string[] | undefined)?.some((use) =>
            use.toLowerCase().includes("git"),
          );

        expect(
          hasContext,
          `child_process finding ${finding.id} should mention git CLI as legitimate use`,
        ).toBe(true);
      }
    });
  });

  describe("baseline extensions", () => {
    it("prettier-vscode has minimal findings", () => {
      const result = scanResults.get("esbenp.prettier-vscode");
      if (!result) return;

      // A simple formatter shouldn't have many security findings
      // Allow some informational findings but no high/critical
      const highSeverityFindings = result.findings.filter(
        (f) => f.severity === "high" || f.severity === "critical",
      );

      expect(
        highSeverityFindings.length,
        `Simple formatter should not have high/critical findings: ${highSeverityFindings.map((f) => f.id).join(", ")}`,
      ).toBe(0);
    });
  });
});

describe("finding structure", () => {
  function createMockFinding(overrides: Partial<Finding> = {}): Finding {
    return {
      id: "TEST_FINDING",
      title: "Test finding title",
      description: "This is a test finding with a description that is long enough to pass validation",
      severity: "medium",
      category: "pattern",
      location: {
        file: "test.js",
        line: 42,
      },
      metadata: {
        matched: "test pattern",
        legitimateUses: ["Testing", "Documentation"],
        redFlags: ["Combined with other suspicious patterns"],
      },
      ...overrides,
    };
  }

  it("validates finding has all required fields", () => {
    const finding = createMockFinding();

    expect(finding.id).toBeDefined();
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.description.length).toBeGreaterThan(50);
    expect(finding.severity).toMatch(/^(low|medium|high|critical)$/);
    expect(finding.category).toBeDefined();
    expect(finding.location?.file).toBeDefined();
  });

  it("validates metadata structure", () => {
    const finding = createMockFinding();

    expect(finding.metadata?.["matched"]).toBeDefined();
    expect(finding.metadata?.["legitimateUses"]).toBeInstanceOf(Array);
    expect(finding.metadata?.["redFlags"]).toBeInstanceOf(Array);
  });

  it("description mentions context for triage", () => {
    const finding = createMockFinding({
      description:
        "Code uses child_process module. Common in extensions that run CLI tools (git, compilers, linters). Review the commands being executed.",
    });

    const descLower = finding.description.toLowerCase();
    const hasTriageContext =
      descLower.includes("common") ||
      descLower.includes("legitimate") ||
      descLower.includes("review");

    expect(hasTriageContext).toBe(true);
  });
});
