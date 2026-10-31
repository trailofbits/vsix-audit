import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { printBatchSummary, toSarif, toSarifCombined } from "#internal/formatters.js";
import type { BatchScanResult, ScanResult } from "#internal/scanner/types.js";

const result: ScanResult = {
  extension: { id: "test.extension", name: "extension", publisher: "test", version: "1.0.0" },
  findings: [
    {
      id: "AST_EVAL_DYNAMIC",
      title: "Dynamic eval",
      description: "eval executes a variable",
      severity: "high",
      category: "ast",
      location: { file: "main file.js", line: 2 },
    },
  ],
  inventory: [],
  metadata: { scannedAt: "2026-10-31T00:00:00Z", scanDuration: 1 },
};

function failedBatch(): BatchScanResult {
  return {
    results: [],
    errors: [{ path: "/extensions/broken", error: "Invalid extension: missing package.json" }],
    summary: {
      totalFiles: 1,
      scannedFiles: 0,
      failedFiles: 1,
      totalFindings: 0,
      findingsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
      scanDuration: 1,
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("installed scan reports", () => {
  it("uses absolute file URIs and records each installed source in SARIF", () => {
    const sourcePath = join(tmpdir(), "editor extensions", "test.extension-1.0.0");
    const sarif = toSarif({ ...result, metadata: { ...result.metadata, sourcePath } }, "0.3.0");
    const run = sarif.runs[0];

    expect(run).toMatchObject({ properties: { sourcePath } });
    expect(run?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      pathToFileURL(join(sourcePath, "main file.js")).href,
    );
  });

  it("keeps existing relative SARIF locations for scans without an installed source", () => {
    expect(
      toSarif(result, "0.3.0").runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation
        .uri,
    ).toBe("main file.js");
  });

  it("includes errors when every extension failed to scan", () => {
    const batch = failedBatch();
    const sarif = toSarifCombined([], "0.3.0", batch.errors);

    expect(sarif).toMatchObject({
      runs: [
        {
          invocations: [
            {
              executionSuccessful: false,
              toolExecutionNotifications: [
                {
                  level: "error",
                  message: { text: expect.stringContaining("/extensions/broken") },
                },
              ],
            },
          ],
        },
      ],
    });
  });

  it("includes successes and errors in the same SARIF report", () => {
    const sarif = toSarifCombined([result], "0.3.0", failedBatch().errors);
    expect(sarif.runs).toHaveLength(2);
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe("AST_EVAL_DYNAMIC");
    expect(sarif.runs[1]?.invocations?.[0]?.executionSuccessful).toBe(false);
  });

  it("prints failed paths even when the batch has no findings", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    printBatchSummary(failedBatch());
    const text = log.mock.calls.flat().join("\n");

    expect(text).toContain("/extensions/broken");
    expect(text).toContain("missing package.json");
    expect(text).not.toContain("No issues found across all extensions");
  });

  it("includes installed paths beside text findings", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const batch = failedBatch();
    batch.results = [{ ...result, metadata: { ...result.metadata, sourcePath: "/my/editor" } }];
    batch.summary.totalFindings = 1;
    printBatchSummary(batch);
    expect(log.mock.calls.flat().join("\n")).toContain("/my/editor");
  });
});

describe("batch diagnostics", () => {
  it("shows timing data for clean batch results", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const batch = failedBatch();
    batch.results = [
      {
        ...result,
        findings: [],
        metadata: { ...result.metadata, timings: { load: 1, ast: 1, total: 2 } },
      },
    ];
    printBatchSummary(batch);
    expect(log.mock.calls.flat().join("\n")).toContain("Module timings:");
  });

  it("reports degraded coverage even when severity filtering leaves no findings", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const batch = failedBatch();
    batch.errors = [];
    batch.summary.failedFiles = 0;
    batch.results = [
      {
        ...result,
        findings: [],
        metadata: {
          ...result.metadata,
          coverage: {
            degraded: true,
            warnings: ["YARA unavailable"],
            unavailableModules: ["yara"],
          },
        },
      },
    ];
    printBatchSummary(batch);
    const text = log.mock.calls.flat().join("\n");
    expect(text).toContain("YARA unavailable");
    expect(text).not.toContain("No issues found across all extensions");
  });
});
