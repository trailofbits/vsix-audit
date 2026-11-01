import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  printBatchSummary,
  printTextReport,
  toSarif,
  toSarifCombined,
} from "#internal/formatters.js";
import type { BatchScanResult, ScanResult } from "#internal/scanner/types.js";

const result: ScanResult = {
  observations: [],
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
  metadata: {
    scannedAt: "2026-10-31T00:00:00Z",
    scanDuration: 1,
    coverage: { degraded: false, warnings: [], incompleteModules: [] },
  },
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

describe("registry batch reports", () => {
  it.each([0, 1])("attributes each registry with %s findings per scan", (count) => {
    const registries = ["marketplace", "openvsx", "cursor"] as const;
    const results = registries.map((registry, index): ScanResult => ({
      ...result,
      extension: { ...result.extension, version: `1.${index}.0` },
      findings: result.findings.slice(0, count),
      metadata: { ...result.metadata, registry },
    }));
    const sarif = toSarifCombined(results, "0.3.0");
    expect(sarif.runs.map((run) => run.properties)).toEqual(
      registries.map((registry) => ({
        registry,
        observations: [],
        coverage: result.metadata.coverage,
      })),
    );
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    printBatchSummary({
      results,
      errors: [],
      summary: {
        totalFiles: 3,
        scannedFiles: 3,
        failedFiles: 0,
        totalFindings: 3 * count,
        findingsBySeverity: { low: 0, medium: 0, high: 3 * count, critical: 0 },
        scanDuration: 1,
      },
    });
    const text = log.mock.calls.flat().join("\n");
    for (const [index, registry] of registries.entries()) {
      expect(text).toContain(`${registry}: test.extension@1.${index}.0`);
    }
  });
});

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
                },
              ],
            },
          ],
        },
      ],
    });
    expect(sarif.runs[0]?.invocations?.[0]?.toolExecutionNotifications[0]?.message.text).toContain(
      "/extensions/broken",
    );
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
  it("marks coverage failures even if the warning list is empty", () => {
    const scan = {
      ...result,
      metadata: {
        ...result.metadata,
        coverage: {
          degraded: true,
          warnings: [],
          incompleteModules: [],
        },
      },
    };
    const report = toSarif(scan, "test");
    expect(report.runs[0]?.invocations?.[0]?.executionSuccessful).toBe(false);
    expect(report.runs[0]?.invocations?.[0]?.toolExecutionNotifications[0]?.message.text).toContain(
      "Incomplete scan coverage",
    );
  });

  it("does not print a clean verdict for an incomplete individual scan", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const scan = {
      ...result,
      findings: [],
      metadata: {
        ...result.metadata,
        coverage: {
          degraded: true,
          warnings: ["Native behavior is unexamined"],
          incompleteModules: [],
        },
      },
    };
    printTextReport(scan);
    const text = log.mock.calls.flat().join("\n");
    expect(text).toContain("scan is incomplete");
    expect(text).not.toContain("No security issues found");
  });

  it("escapes every untrusted part of a batch report", () => {
    const attack = "bad\x1b[8m\r\u202e";
    const scan: ScanResult = {
      ...result,
      extension: { ...result.extension, name: attack, version: attack },
      findings: result.findings.map((finding) => ({
        ...finding,
        title: attack,
        description: attack,
        location: { file: attack },
        metadata: { matches: [{ identifier: attack, offset: 0, match: attack }] },
      })),
      metadata: {
        ...result.metadata,
        sourcePath: attack,
        coverage: {
          degraded: true,
          warnings: [attack],
          incompleteModules: [],
        },
      },
    };
    const batch = failedBatch();
    batch.errors = [{ path: attack, error: attack }];
    batch.results = [scan];
    batch.summary.totalFindings = 1;
    batch.discovery = { roots: [attack], scope: attack };
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    printBatchSummary(batch);
    const text = log.mock.calls.flat().join("\n");
    expect(text).not.toContain("\x1b[8m");
    expect(text).not.toContain("\r");
    expect(text).not.toContain("\u202e");
    expect(text).toContain("\\x1b[8m");
  });
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
            incompleteModules: ["yara"],
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
