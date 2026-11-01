import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import pc from "picocolors";
import { reportJson, terminalText } from "#internal/terminal.js";
import type {
  BatchScanResult,
  CoverageMetadata,
  Finding,
  FindingMetadata,
  InstalledScanScope,
  ModuleTimings,
  Observation,
  Registry,
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
  properties?: FindingMetadata;
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine?: number; startColumn?: number; byteOffset?: number } | undefined;
    };
  }>;
}

interface SarifRun {
  columnKind: "utf16CodeUnits";
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  properties?: {
    sourcePath?: string;
    registry?: Registry;
    coverage?: CoverageMetadata;
    discovery?: InstalledScanScope;
    observations?: Observation[];
  };
  invocations?: Array<{
    executionSuccessful: boolean;
    toolExecutionNotifications: Array<{ level: "error" | "warning"; message: { text: string } }>;
  }>;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

function locationSuffix(location: NonNullable<Finding["location"]>): string {
  if (location.line !== undefined && location.line > 0) {
    return `:${location.line}` + (location.column === undefined ? "" : `:${location.column}`);
  }
  return location.byteOffset === undefined ? "" : ` (byte ${location.byteOffset})`;
}

function sarifTextRegion(location: NonNullable<Finding["location"]>): {
  startLine?: number;
  startColumn?: number;
} {
  const region: { startLine?: number; startColumn?: number } = {};
  if (location.line !== undefined && Number.isInteger(location.line) && location.line > 0) {
    region.startLine = location.line;
    if (location.column !== undefined && Number.isInteger(location.column) && location.column > 0) {
      region.startColumn = location.column;
    }
  }
  return region;
}

function sarifRegion(
  location: NonNullable<Finding["location"]>,
): SarifResult["locations"][number]["physicalLocation"]["region"] {
  const region: NonNullable<SarifResult["locations"][number]["physicalLocation"]["region"]> =
    sarifTextRegion(location);
  if (
    location.byteOffset !== undefined &&
    Number.isSafeInteger(location.byteOffset) &&
    location.byteOffset >= 0
  )
    region.byteOffset = location.byteOffset;
  return Object.keys(region).length === 0 ? undefined : region;
}

function sarifCoverage(run: SarifRun, coverage: CoverageMetadata): void {
  if (!coverage.degraded) return;
  run.properties = { ...run.properties, coverage };
  const warnings =
    coverage.warnings.length > 0
      ? coverage.warnings
      : [`Incomplete scan coverage: ${coverage.incompleteModules.join(", ") || "unknown cause"}`];
  run.invocations = [
    {
      executionSuccessful: false,
      toolExecutionNotifications: warnings.map((text) => ({ level: "warning", message: { text } })),
    },
  ];
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
    columnKind: "utf16CodeUnits",
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

/** Encode findings as SARIF, retaining installed paths and registry attribution. */
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
  run.properties = { observations: result.observations, coverage: result.metadata.coverage };
  const { sourcePath, registry } = result.metadata;
  if (sourcePath !== undefined || registry !== undefined) {
    run.properties = {
      ...run.properties,
      ...(sourcePath === undefined ? {} : { sourcePath }),
      ...(registry === undefined ? {} : { registry }),
    };
  }
  run.results = result.findings.map((f) => ({
    ruleId: f.id,
    level: severityToSarifLevel(f.severity),
    message: { text: f.description },
    ...(f.metadata === undefined ? {} : { properties: f.metadata }),
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
              region: sarifRegion(f.location),
            },
          },
        ]
      : [],
  }));
  sarifCoverage(run, result.metadata.coverage);
  return { $schema: SARIF_SCHEMA, version: "2.1.0", runs: [run] };
}

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

/** Combine scans into SARIF and retain batch failures as tool execution notifications. */
export function toSarifCombined(
  results: ScanResult[],
  toolVersion: string,
  errors: BatchScanResult["errors"] = [],
  discovery?: InstalledScanScope,
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
  if (discovery !== undefined) {
    if (runs.length === 0) runs.push(createSarifRun(toolVersion, []));
    for (const run of runs) run.properties = { ...run.properties, discovery };
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
    entries.push([terminalText(displayName(key)), value]);
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

function printCheckInventory(inventory: ScanResult["inventory"]): void {
  if (inventory.length === 0) return;
  console.log(pc.cyan("Checks performed:"));
  for (const check of inventory) {
    if (check.enabled) {
      console.log(
        `  ${pc.green("✓")} ${pc.bold(terminalText(check.name).padEnd(14))}` +
          terminalText(check.description),
      );
    } else {
      console.log(
        `  ${pc.yellow("⚠")} ${pc.bold(terminalText(check.name).padEnd(14))}` +
          pc.dim(`Skipped (${terminalText(check.skipReason)})`),
      );
    }
  }
  console.log();
}

function printCoverageWarnings(coverage: ScanResult["metadata"]["coverage"]): void {
  if (!coverage.degraded) return;
  console.log(pc.yellow("Coverage degraded:"));
  for (const warning of coverage.warnings.slice(0, 10)) {
    console.log(`  ${pc.yellow("⚠")} ${terminalText(warning)}`);
  }
  if (coverage.warnings.length > 10) {
    console.log(`  ${pc.dim(`... and ${coverage.warnings.length - 10} more`)}`);
  }
  console.log();
}

function printSource(result: ScanResult): void {
  if (result.metadata.registry !== undefined)
    console.log(`Registry: ${terminalText(result.metadata.registry)}`);
  if (result.metadata.sourcePath !== undefined)
    console.log(`Path: ${terminalText(result.metadata.sourcePath)}`);
}

function printFinding(finding: Finding): void {
  const color = severityColor(finding.severity);
  console.log(`  ${color(`[${finding.severity.toUpperCase()}]`)} ${terminalText(finding.title)}`);
  console.log(`  ${pc.dim(terminalText(finding.description))}`);
  if (finding.location) {
    console.log(
      `  ${pc.dim(`at ${terminalText(finding.location.file)}` + locationSuffix(finding.location))}`,
    );
  }
  const matches = finding.metadata?.matches ?? [];
  for (const match of matches.slice(0, 5)) {
    console.log(
      `  ${terminalText(match.identifier)} at byte ${match.offset}: ` + terminalText(match.match),
    );
  }
  const remaining = (finding.metadata?.totalMatches ?? matches.length) - 5;
  if (remaining > 0) {
    console.log(`  ... and ${remaining} more string matches. JSON/SARIF retains up to 20.`);
  }
  console.log();
}

export function printTextReport(result: ScanResult): void {
  console.log();
  console.log(pc.bold("vsix-audit scan results"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(
    `${pc.cyan("Extension:")} ${terminalText(result.extension.name)} ` +
      `v${terminalText(result.extension.version)}`,
  );
  console.log(
    `${pc.cyan("Publisher:")} ${terminalText(result.extension.publisher ?? "(unknown)")}`,
  );
  printSource(result);
  console.log(`${pc.cyan("Scanned:")} ${terminalText(result.metadata.scannedAt)}`);
  console.log();

  printCheckInventory(result.inventory);

  if (result.metadata.timings) {
    printTimings(result.metadata.timings);
  }

  printCoverageWarnings(result.metadata.coverage);
  printObservations(result.observations);

  if (result.findings.length === 0) {
    console.log(
      result.metadata.coverage.degraded
        ? pc.yellow("No findings in completed checks. The scan is incomplete.")
        : pc.green("✓ No findings at the selected severity."),
    );
    return;
  }

  console.log(pc.yellow(`Found ${result.findings.length} issue(s):`));
  console.log();

  for (const finding of result.findings) printFinding(finding);
}

function printObservations(observations: Observation[]): void {
  if (observations.length === 0) return;
  console.log(pc.cyan(`Source observations (${observations.length}):`));
  for (const item of observations.slice(0, 20)) {
    const location = `${item.location.file}:${item.location.line}:${item.location.column}`;
    console.log(`  ${terminalText(item.kind)} ${terminalText(item.api)} ${terminalText(location)}`);
    console.log(`    ${terminalText(item.snippet)}`);
  }
  if (observations.length > 20) {
    console.log(
      `  ${observations.length - 20} more observations. Use JSON or SARIF for all evidence.`,
    );
  }
  console.log();
}

function printBatchFindings(results: ScanResult[]): void {
  const withFindings = results.filter((r) => r.findings.length > 0);
  if (withFindings.length > 0) {
    console.log(pc.cyan("Extensions with findings:"));
    console.log();
    for (const r of withFindings) {
      console.log(pc.bold(terminalText(`${r.extension.name} v${r.extension.version}`)));
      printSource(r);
      console.log(pc.dim("─".repeat(40)));
      for (const finding of r.findings) printFinding(finding);
    }
  }
}

function printBatchErrors(errors: BatchScanResult["errors"]): void {
  if (errors.length > 0) {
    console.log();
    console.log(pc.cyan("Failed targets:"));
    for (const e of errors) {
      console.log(`  - ${terminalText(e.path)}`);
      console.log(`    ${pc.dim(terminalText(e.error))}`);
    }
  }
}

function printBatchTimings(results: ScanResult[]): void {
  for (const result of results) {
    if (!result.metadata.timings) continue;
    console.log(pc.bold(terminalText(`${result.extension.name} v${result.extension.version}`)));
    printSource(result);
    printTimings(result.metadata.timings);
  }
}

function printBatchCoverage(results: ScanResult[]): void {
  for (const result of results) {
    const coverage = result.metadata.coverage;
    if (coverage.degraded !== true) continue;
    const source = result.metadata.sourcePath ?? result.extension.id;
    const registry = result.metadata.registry;
    const label = registry === undefined ? source : `${registry}:${source}`;
    console.log(pc.yellow(`Coverage degraded: ${terminalText(label)}`));
    for (const warning of coverage.warnings) console.log(`  ${terminalText(warning)}`);
    console.log();
  }
}

function printRegistryResults(results: ScanResult[]): void {
  const rows = results.flatMap((result) => {
    const registry = result.metadata.registry;
    if (registry === undefined) return [];
    return [
      `${registry}: ${result.extension.id}@${result.extension.version} ` +
        `(${result.findings.length} finding(s))`,
    ];
  });
  if (rows.length === 0) return;
  console.log(pc.cyan("Registry results:"));
  for (const row of rows) console.log(`  ${terminalText(row)}`);
  console.log();
}

function printDiscovery(discovery: InstalledScanScope | undefined, results: ScanResult[]): void {
  if (discovery === undefined) return;
  console.log(`Scope: ${terminalText(discovery.scope)}`);
  for (const root of discovery.roots) console.log(`Store: ${terminalText(root)}`);
  for (const result of results) {
    console.log(`Scanned extension: ${terminalText(result.metadata.sourcePath)}`);
  }
  console.log();
}

/** Print batch findings and failures without hiding incomplete scanner coverage. */
export function printBatchSummary(batch: BatchScanResult): void {
  const { summary, results, errors } = batch;
  console.log();
  console.log(pc.bold("Batch Scan Summary"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`Targets scanned: ${summary.scannedFiles}/${summary.totalFiles}`);
  if (summary.failedFiles > 0) console.log(`Failed: ${pc.red(String(summary.failedFiles))}`);
  console.log(`Duration: ${(summary.scanDuration / 1000).toFixed(1)}s`);
  console.log();
  printDiscovery(batch.discovery, results);
  printBatchErrors(errors);
  printRegistryResults(results);
  printBatchTimings(results);
  printBatchCoverage(results);
  for (const result of results.filter((item) => item.observations.length > 0)) {
    console.log(terminalText(result.metadata.sourcePath ?? result.extension.id));
    printObservations(result.observations);
  }
  const incomplete =
    summary.failedFiles > 0 || results.some((result) => result.metadata.coverage.degraded === true);
  if (summary.totalFindings === 0) {
    const message = incomplete
      ? "No findings in completed checks. The scan is incomplete."
      : "No findings at the selected severity across all extensions.";
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
    console.log(reportJson(result));
  } else if (format === "sarif") {
    console.log(reportJson(toSarif(result, toolVersion)));
  } else {
    printTextReport(result);
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
    console.log(reportJson(batchResult));
  } else if (format === "sarif") {
    console.log(
      reportJson(
        toSarifCombined(
          batchResult.results,
          toolVersion,
          batchResult.errors,
          batchResult.discovery,
        ),
      ),
    );
  } else {
    printBatchSummary(batchResult);
  }
}
