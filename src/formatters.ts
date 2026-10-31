import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import pc from "picocolors";
import type {
  BatchScanResult,
  ModuleTimings,
  ScanResult,
  Severity,
} from "#internal/scanner/types.js";

type SarifLevel = "none" | "note" | "warning" | "error";

interface SarifRule {
  id: string;
  shortDescription: { text: string };
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number } | undefined;
    };
  }>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  properties?: { sourcePath: string };
  invocations?: Array<{
    executionSuccessful: boolean;
    toolExecutionNotifications: Array<{ level: "error"; message: { text: string } }>;
  }>;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

function locationLineSuffix(line: number | undefined): string {
  return line !== undefined && line !== 0 && !Number.isNaN(line) ? `:${line}` : "";
}

function severityToSarifLevel(severity: Severity): SarifLevel {
  const mapping: Record<Severity, SarifLevel> = {
    low: "note",
    medium: "warning",
    high: "error",
    critical: "error",
  };
  return mapping[severity];
}

function createSarifRun(toolVersion: string, rules: SarifRule[]): SarifRun {
  return {
    tool: {
      driver: {
        name: "vsix-audit",
        version: toolVersion,
        informationUri: "https://github.com/trailofbits/vsix-audit",
        rules,
      },
    },
    results: [],
  };
}

/** Encode findings as SARIF, retaining the source directory for installed scans. */
export function toSarif(result: ScanResult, toolVersion: string): SarifReport {
  const seenRuleIds = new Set<string>();
  const rules: SarifRule[] = [];
  for (const f of result.findings) {
    if (!seenRuleIds.has(f.id)) {
      seenRuleIds.add(f.id);
      rules.push({
        id: f.id,
        shortDescription: { text: f.title },
      });
    }
  }

  const run = createSarifRun(toolVersion, rules);
  const sourcePath = result.metadata.sourcePath;
  if (sourcePath !== undefined) run.properties = { sourcePath };
  run.results = result.findings.map((f) => ({
    ruleId: f.id,
    level: severityToSarifLevel(f.severity),
    message: { text: f.description },
    locations: f.location
      ? [
          {
            physicalLocation: {
              artifactLocation: {
                uri:
                  sourcePath === undefined
                    ? f.location.file
                    : pathToFileURL(resolve(sourcePath, f.location.file)).href,
              },
              region:
                f.location.line !== undefined &&
                f.location.line !== 0 &&
                !Number.isNaN(f.location.line)
                  ? { startLine: f.location.line }
                  : undefined,
            },
          },
        ]
      : [],
  }));
  return { $schema: SARIF_SCHEMA, version: "2.1.0", runs: [run] };
}

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

/** Combine scans into SARIF and retain batch failures as tool execution notifications. */
export function toSarifCombined(
  results: ScanResult[],
  toolVersion: string,
  errors: BatchScanResult["errors"] = [],
): SarifReport {
  const runs = results.flatMap((result) => toSarif(result, toolVersion).runs);
  if (errors.length > 0) {
    const run = createSarifRun(toolVersion, []);
    run.invocations = [
      {
        executionSuccessful: false,
        toolExecutionNotifications: errors.map(({ path, error }) => ({
          level: "error",
          message: { text: `Could not scan ${path}: ${error}` },
        })),
      },
    ];
    runs.push(run);
  }
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs,
  };
}

function severityColor(severity: Severity): (s: string) => string {
  return { critical: pc.red, high: pc.red, medium: pc.yellow, low: pc.blue }[severity];
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

export function formatFindingSummary(findings: Array<{ severity: Severity }>): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  const parts: string[] = [];
  if (counts.critical > 0) parts.push(`${counts.critical} critical`);
  if (counts.high > 0) parts.push(`${counts.high} high`);
  if (counts.medium > 0) parts.push(`${counts.medium} medium`);
  if (counts.low > 0) parts.push(`${counts.low} low`);
  return parts.join(", ");
}

/** Capitalize module name for display */
function displayName(key: string): string {
  if (key === "ast" || key === "ioc") return key.toUpperCase();
  if (key === "yara") return "YARA";
  return key.charAt(0).toUpperCase() + key.slice(1);
}

function printTimings(timings: ModuleTimings): void {
  console.log(pc.cyan("Module timings:"));

  const entries: [string, number][] = [["Load", timings.load]];
  for (const [key, value] of Object.entries(timings)) {
    if (key === "load" || key === "total") continue;
    entries.push([displayName(key), value]);
  }

  const maxNameLen = Math.max(...entries.map(([name]) => name.length));
  const moduleTotal = entries.reduce((sum, [, ms]) => sum + ms, 0);

  for (const [name, ms] of entries) {
    const pct = moduleTotal > 0 ? (ms / moduleTotal) * 100 : 0;
    const barLen = Math.round(pct / 2);
    const bar = "█".repeat(barLen);
    const padded = name.padEnd(maxNameLen);
    const timeStr = formatMs(ms).padStart(8);
    const pctStr = `${pct.toFixed(1)}%`.padStart(6);
    console.log(`  ${pc.bold(padded)} ${timeStr} ${pctStr} ${pc.dim(bar)}`);
  }

  console.log(`  ${"─".repeat(maxNameLen + 20)}`);
  console.log(`  ${pc.bold("Total".padEnd(maxNameLen))} ${formatMs(timings.total).padStart(8)}`);
  console.log();
}

export function printTextReport(result: ScanResult): void {
  console.log();
  console.log(pc.bold("vsix-audit scan results"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`${pc.cyan("Extension:")} ${result.extension.name} v${result.extension.version}`);
  console.log(`${pc.cyan("Publisher:")} ${result.extension.publisher}`);
  console.log(`${pc.cyan("Scanned:")} ${result.metadata.scannedAt}`);
  console.log();

  if (result.inventory.length > 0) {
    console.log(pc.cyan("Checks performed:"));
    for (const check of result.inventory) {
      if (check.enabled) {
        console.log(`  ${pc.green("✓")} ${pc.bold(check.name.padEnd(14))}${check.description}`);
      } else {
        console.log(
          `  ${pc.yellow("⚠")} ${pc.bold(check.name.padEnd(14))}` +
            pc.dim(`Skipped (${check.skipReason})`),
        );
      }
    }
    console.log();
  }

  if (result.metadata.timings) {
    printTimings(result.metadata.timings);
  }

  if (result.metadata.coverage?.degraded === true) {
    console.log(pc.yellow("Coverage degraded:"));
    for (const warning of result.metadata.coverage.warnings.slice(0, 10)) {
      console.log(`  ${pc.yellow("⚠")} ${warning}`);
    }
    if (result.metadata.coverage.warnings.length > 10) {
      console.log(`  ${pc.dim(`... and ${result.metadata.coverage.warnings.length - 10} more`)}`);
    }
    console.log();
  }

  if (result.findings.length === 0) {
    console.log(pc.green("✓ No security issues found"));
    return;
  }

  console.log(pc.yellow(`Found ${result.findings.length} issue(s):`));
  console.log();

  for (const finding of result.findings) {
    const color = severityColor(finding.severity);
    console.log(`  ${color(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
    console.log(`  ${pc.dim(finding.description)}`);
    if (finding.location) {
      console.log(
        `  ${pc.dim(`at ${finding.location.file}${locationLineSuffix(finding.location.line)}`)}`,
      );
    }
    console.log();
  }
}

function printBatchFindings(results: ScanResult[]): void {
  const withFindings = results.filter((r) => r.findings.length > 0);
  if (withFindings.length > 0) {
    console.log(pc.cyan("Extensions with findings:"));
    console.log();
    for (const r of withFindings) {
      console.log(pc.bold(`${r.extension.name} v${r.extension.version}`));
      if (r.metadata.sourcePath !== undefined) console.log(`Path: ${r.metadata.sourcePath}`);
      console.log(pc.dim("─".repeat(40)));
      for (const finding of r.findings) {
        const color = severityColor(finding.severity);
        console.log(`  ${color(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
        console.log(`  ${pc.dim(finding.description)}`);
        if (finding.location) {
          const { file, line } = finding.location;
          console.log(`  ${pc.dim(`at ${file}${locationLineSuffix(line)}`)}`);
        }
        console.log();
      }
    }
  }
}

function printBatchErrors(errors: BatchScanResult["errors"]): void {
  if (errors.length > 0) {
    console.log();
    console.log(pc.cyan("Failed targets:"));
    for (const e of errors) {
      console.log(`  - ${e.path}`);
      console.log(`    ${pc.dim(e.error)}`);
    }
  }
}

function printBatchTimings(results: ScanResult[]): void {
  for (const result of results) {
    if (!result.metadata.timings) continue;
    console.log(pc.bold(`${result.extension.name} v${result.extension.version}`));
    if (result.metadata.sourcePath !== undefined)
      console.log(`Path: ${result.metadata.sourcePath}`);
    printTimings(result.metadata.timings);
  }
}

function printBatchCoverage(results: ScanResult[]): void {
  for (const result of results) {
    const coverage = result.metadata.coverage;
    if (coverage?.degraded !== true) continue;
    const source = result.metadata.sourcePath ?? result.extension.id;
    console.log(pc.yellow(`Coverage degraded: ${source}`));
    for (const warning of coverage.warnings) console.log(`  ${warning}`);
    console.log();
  }
}

/** Print batch findings and failures without hiding incomplete scanner coverage. */
export function printBatchSummary(batch: BatchScanResult): void {
  const { summary, results, errors } = batch;
  console.log();
  console.log(pc.bold("Batch Scan Summary"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`Extensions scanned: ${summary.scannedFiles}/${summary.totalFiles}`);
  if (summary.failedFiles > 0) console.log(`Failed: ${pc.red(String(summary.failedFiles))}`);
  console.log(`Duration: ${(summary.scanDuration / 1000).toFixed(1)}s`);
  console.log();
  printBatchErrors(errors);
  printBatchTimings(results);
  printBatchCoverage(results);
  const incomplete =
    summary.failedFiles > 0 ||
    results.some((result) => result.metadata.coverage?.degraded === true);
  if (summary.totalFindings === 0) {
    const message = incomplete
      ? "No findings in completed checks. The scan is incomplete."
      : "No issues found across all extensions";
    console.log(incomplete ? pc.yellow(message) : pc.green(message));
    return;
  }
  console.log(pc.yellow(`Found ${summary.totalFindings} issue(s) across all extensions:`));
  for (const severity of ["critical", "high", "medium", "low"] as const) {
    const count = summary.findingsBySeverity[severity];
    if (count > 0) console.log(`  ${severityColor(severity)(displayName(severity))}: ${count}`);
  }
  console.log();
  printBatchFindings(results);
}

/**
 * Dispatch scan output to the appropriate formatter.
 */
export function outputResult(result: ScanResult, format: string, toolVersion: string): void {
  if (format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else if (format === "sarif") {
    console.log(JSON.stringify(toSarif(result, toolVersion), null, 2));
  } else {
    printTextReport(result);
  }
}

/**
 * Dispatch combined multi-result output.
 */
export function outputResults(results: ScanResult[], format: string, toolVersion: string): void {
  if (format === "json") {
    console.log(JSON.stringify(results, null, 2));
  } else if (format === "sarif") {
    console.log(JSON.stringify(toSarifCombined(results, toolVersion), null, 2));
  } else {
    for (const result of results) {
      const registry = (result.metadata as { registry?: string }).registry ?? "unknown";
      console.log(pc.bold(`Registry: ${registry}`));
      printTextReport(result);
      console.log();
    }
  }
}

/**
 * Dispatch batch result output.
 */
export function outputBatchResult(
  batchResult: BatchScanResult,
  format: string,
  toolVersion: string,
): void {
  if (format === "json") {
    console.log(JSON.stringify(batchResult, null, 2));
  } else if (format === "sarif") {
    console.log(
      JSON.stringify(
        toSarifCombined(batchResult.results, toolVersion, batchResult.errors),
        null,
        2,
      ),
    );
  } else {
    printBatchSummary(batchResult);
  }
}
