import pc from "picocolors";
import type { BatchScanResult, ModuleTimings, ScanResult, Severity } from "./scanner/types.js";

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
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
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

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "vsix-audit",
            version: toolVersion,
            informationUri: "https://github.com/trailofbits/vsix-audit",
            rules,
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: severityToSarifLevel(f.severity),
          message: { text: f.description },
          locations: f.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: f.location.file,
                    },
                    region: f.location.line ? { startLine: f.location.line } : undefined,
                  },
                },
              ]
            : [],
        })),
      },
    ],
  };
}

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

export function toSarifCombined(results: ScanResult[], toolVersion: string): object {
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: results.map((r) => toSarif(r, toolVersion).runs[0]),
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

  if (result.inventory && result.inventory.length > 0) {
    console.log(pc.cyan("Checks performed:"));
    for (const check of result.inventory) {
      if (check.enabled) {
        console.log(`  ${pc.green("✓")} ${pc.bold(check.name.padEnd(14))}${check.description}`);
      } else {
        console.log(
          `  ${pc.yellow("⚠")} ${pc.bold(check.name.padEnd(14))}${pc.dim(`Skipped (${check.skipReason})`)}`,
        );
      }
    }
    console.log();
  }

  if (result.metadata.timings) {
    printTimings(result.metadata.timings);
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
        `  ${pc.dim(`at ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`)}`,
      );
    }
    console.log();
  }
}

export function printBatchSummary(batch: BatchScanResult): void {
  const { summary, results, errors } = batch;

  console.log();
  console.log(pc.bold("Batch Scan Summary"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`Files scanned: ${summary.scannedFiles}/${summary.totalFiles}`);
  if (summary.failedFiles > 0) {
    console.log(`Failed: ${pc.red(String(summary.failedFiles))}`);
  }
  console.log(`Duration: ${(summary.scanDuration / 1000).toFixed(1)}s`);
  console.log();

  if (summary.totalFindings === 0) {
    console.log(pc.green("No issues found across all extensions"));
    return;
  }

  console.log(pc.yellow(`Found ${summary.totalFindings} issue(s) across all extensions:`));
  const sev = summary.findingsBySeverity;
  if (sev.critical > 0) console.log(`  ${pc.red("Critical:")} ${sev.critical}`);
  if (sev.high > 0) console.log(`  ${pc.red("High:")} ${sev.high}`);
  if (sev.medium > 0) console.log(`  ${pc.yellow("Medium:")} ${sev.medium}`);
  if (sev.low > 0) console.log(`  ${pc.blue("Low:")} ${sev.low}`);
  console.log();

  const withFindings = results.filter((r) => r.findings.length > 0);
  if (withFindings.length > 0) {
    console.log(pc.cyan("Extensions with findings:"));
    console.log();
    for (const r of withFindings) {
      console.log(pc.bold(`${r.extension.name} v${r.extension.version}`));
      console.log(pc.dim("─".repeat(40)));
      for (const finding of r.findings) {
        const color = severityColor(finding.severity);
        console.log(`  ${color(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
        console.log(`  ${pc.dim(finding.description)}`);
        if (finding.location) {
          console.log(
            `  ${pc.dim(`at ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`)}`,
          );
        }
        console.log();
      }
    }
  }

  if (errors.length > 0) {
    console.log();
    console.log(pc.cyan("Failed files:"));
    for (const e of errors) {
      console.log(`  - ${e.path}`);
      console.log(`    ${pc.dim(e.error)}`);
    }
  }
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
    console.log(JSON.stringify(toSarifCombined(batchResult.results, toolVersion), null, 2));
  } else {
    printBatchSummary(batchResult);
  }
}
