import { rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { downloadExtension, parseExtensionId } from "./scanner/download.js";
import { scanDirectory, scanExtension } from "./scanner/index.js";
import type { BatchScanResult, Registry, ScanOptions, ScanResult, Severity } from "./scanner/types.js";
import { loadExtension } from "./scanner/vsix.js";

const REGISTRIES: Registry[] = ["marketplace", "openvsx"];

interface CliScanOptions extends ScanOptions {
  allRegistries?: boolean;
  recursive?: boolean;
  jobs?: string;
}

/**
 * Strip registry prefix from an extension ID for path-checking purposes
 */
function stripRegistryPrefix(target: string): string {
  if (target.startsWith("openvsx:")) return target.slice(8);
  if (target.startsWith("marketplace:")) return target.slice(12);
  return target;
}

/**
 * Check if a target looks like an extension ID vs a local path
 */
function isExtensionId(target: string): boolean {
  // Strip registry prefix for path validation
  const id = stripRegistryPrefix(target);

  // Local paths: start with /, ./, ~, or contain path separators
  if (id.startsWith("/") || id.startsWith("./") || id.startsWith("~")) {
    return false;
  }
  if (id.includes("/") || id.includes("\\")) {
    return false;
  }
  // Extension IDs: publisher.name or publisher.name@version
  try {
    parseExtensionId(target);
    return true;
  } catch {
    return false;
  }
}

export const cli = new Command()
  .name("vsix-audit")
  .description("Security scanner for VS Code extensions")
  .version("0.1.0");

cli
  .command("scan")
  .description("Scan a VS Code extension for security issues")
  .argument("<target>", "Path to .vsix file or extension ID (e.g., publisher.extension)")
  .option("-o, --output <format>", "Output format (text, json, sarif)", "text")
  .option(
    "-s, --severity <level>",
    "Minimum severity to report (low, medium, high, critical)",
    "low",
  )
  .option("--no-network", "Disable network-based checks")
  .option("--all-registries", "Scan from all registries (Marketplace + OpenVSX)")
  .option("-r, --recursive", "Recursively scan all .vsix files in a directory")
  .option("-j, --jobs <n>", "Number of parallel scans (default: 4)", "4")
  .action(async (target: string, options: CliScanOptions) => {
    let tempDir: string | undefined;

    async function cleanup(): Promise<void> {
      if (tempDir) {
        await rm(tempDir, { recursive: true, force: true }).catch(() => {});
      }
    }

    try {
      // Handle --all-registries mode for extension IDs
      if (options.allRegistries && isExtensionId(target)) {
        tempDir = join(tmpdir(), `vsix-audit-${Date.now()}`);
        const results: ScanResult[] = [];
        const baseId = stripRegistryPrefix(target);

        for (const registry of REGISTRIES) {
          const prefixedId = `${registry}:${baseId}`;
          try {
            console.log(pc.cyan(`Downloading from ${registry}:`), baseId);
            const downloaded = await downloadExtension(prefixedId, { destDir: tempDir });
            console.log(pc.green("✓ Downloaded"), pc.dim(downloaded.path));

            const result = await scanExtension(downloaded.path, options);
            result.metadata = { ...result.metadata, registry };
            results.push(result);
          } catch (error) {
            // Extension may not exist in this registry - continue
            const msg = error instanceof Error ? error.message : String(error);
            console.log(pc.dim(`  Not found in ${registry}: ${msg}`));
          }
        }
        console.log();

        if (results.length === 0) {
          console.error(pc.red("Error:"), `Extension not found in any registry: ${baseId}`);
          await cleanup();
          process.exit(2);
        }

        // Output results
        if (options.output === "json") {
          console.log(JSON.stringify(results, null, 2));
        } else if (options.output === "sarif") {
          // Combine SARIF results
          const combined = {
            $schema:
              "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: results.map((r) => toSarif(r).runs[0]),
          };
          console.log(JSON.stringify(combined, null, 2));
        } else {
          for (const result of results) {
            const registry = (result.metadata as { registry?: string }).registry ?? "unknown";
            console.log(pc.bold(`Registry: ${registry}`));
            printTextReport(result);
            console.log();
          }
        }

        await cleanup();
        const hasFindings = results.some((r) => r.findings.length > 0);
        process.exit(hasFindings ? 1 : 0);
        return;
      }

      // Warn if -j used without -r
      if (options.jobs && options.jobs !== "4" && !options.recursive) {
        console.log(pc.yellow("Warning:"), "--jobs is only used with --recursive, ignoring");
      }

      // Handle --recursive mode for directories
      if (options.recursive) {
        const targetStat = await stat(target).catch(() => null);
        if (!targetStat?.isDirectory()) {
          console.error(pc.red("Error:"), "--recursive requires a directory path");
          process.exit(2);
        }

        // Validate --jobs
        const concurrency = parseInt(options.jobs ?? "4", 10);
        if (isNaN(concurrency) || concurrency < 1) {
          console.error(pc.red("Error:"), "--jobs must be a positive integer");
          process.exit(2);
        }

        const isParallel = concurrency > 1;

        console.log(pc.cyan("Scanning directory:"), target);
        if (isParallel) {
          console.log(pc.dim(`Parallel mode: ${concurrency} concurrent scans`));
        }
        console.log();

        const batchResult = await scanDirectory(target, options, {
          onProgress: (completed, total, _path) => {
            if (isParallel) {
              // No line clearing in parallel mode - just update progress
              process.stderr.write(`\r[${completed}/${total}] Scanning...`);
            }
            // Sequential mode: progress shown via onResult
          },
          onResult: (_path, result) => {
            if (isParallel) {
              // Clear progress line before printing result
              process.stderr.write("\r\x1b[K");
            } else {
              process.stdout.write("\r\x1b[K");
            }
            const count = result.findings.length;
            if (count === 0) {
              console.log(`[${pc.green("OK")}] ${result.extension.name} v${result.extension.version}`);
            } else {
              const summary = formatFindingSummary(result.findings);
              console.log(
                `[${pc.yellow("WARN")}] ${result.extension.name} v${result.extension.version} - ${count} issue(s) (${summary})`,
              );
            }
          },
          onError: (path, error) => {
            if (isParallel) {
              process.stderr.write("\r\x1b[K");
            } else {
              process.stdout.write("\r\x1b[K");
            }
            console.log(`[${pc.red("ERROR")}] ${basename(path)} - Error: ${error}`);
          },
        }, { concurrency });

        // Output results
        if (options.output === "json") {
          console.log(JSON.stringify(batchResult, null, 2));
        } else if (options.output === "sarif") {
          const combined = {
            $schema:
              "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: batchResult.results.map((r) => toSarif(r).runs[0]),
          };
          console.log(JSON.stringify(combined, null, 2));
        } else {
          printBatchSummary(batchResult);
        }

        // Exit codes: 0=clean, 1=findings, 2=errors only
        if (batchResult.summary.totalFindings > 0) {
          process.exit(1);
        } else if (batchResult.summary.failedFiles > 0 && batchResult.summary.scannedFiles === 0) {
          process.exit(2);
        }
        process.exit(0);
        return;
      }

      // Standard single-registry scan
      let scanTarget = target;
      if (isExtensionId(target)) {
        // Download to temp directory
        tempDir = join(tmpdir(), `vsix-audit-${Date.now()}`);
        console.log(pc.cyan("Downloading:"), target);
        const result = await downloadExtension(target, { destDir: tempDir });
        scanTarget = result.path;
        console.log(pc.green("✓ Downloaded"), pc.dim(result.path));
        console.log();
      }

      const result = await scanExtension(scanTarget, options);
      if (options.output === "json") {
        console.log(JSON.stringify(result, null, 2));
      } else if (options.output === "sarif") {
        console.log(JSON.stringify(toSarif(result), null, 2));
      } else {
        printTextReport(result);
      }
      await cleanup();
      process.exit(result.findings.length > 0 ? 1 : 0);
    } catch (error) {
      await cleanup();
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cli
  .command("download")
  .description("Download a VS Code extension from the marketplace")
  .argument("<extension-id>", "Extension ID (e.g., ms-python.python or ms-python.python@2024.1.0)")
  .option("-o, --output <dir>", "Output directory", process.cwd())
  .action(async (extensionId: string, options: { output: string }) => {
    try {
      console.log(pc.cyan("Downloading:"), extensionId);

      const result = await downloadExtension(extensionId, { destDir: options.output });

      console.log();
      console.log(pc.green("✓ Downloaded successfully"));
      console.log(pc.dim("─".repeat(50)));
      console.log(`${pc.cyan("Name:")} ${result.metadata.displayName ?? result.metadata.name}`);
      console.log(`${pc.cyan("Publisher:")} ${result.metadata.publisher}`);
      console.log(`${pc.cyan("Version:")} ${result.metadata.version}`);
      if (result.metadata.installCount) {
        console.log(`${pc.cyan("Installs:")} ${result.metadata.installCount.toLocaleString()}`);
      }
      console.log(`${pc.cyan("Path:")} ${result.path}`);
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cli
  .command("info")
  .description("Display metadata about a VS Code extension")
  .argument("<target>", "Path to .vsix file or directory")
  .action(async (target: string) => {
    try {
      const contents = await loadExtension(target);
      const manifest = contents.manifest;

      console.log();
      console.log(pc.bold("Extension Info"));
      console.log(pc.dim("─".repeat(50)));
      console.log();
      console.log(`${pc.cyan("Name:")} ${manifest.displayName ?? manifest.name}`);
      console.log(`${pc.cyan("Publisher:")} ${manifest.publisher}`);
      console.log(`${pc.cyan("Version:")} ${manifest.version}`);
      if (manifest.description) {
        console.log(`${pc.cyan("Description:")} ${manifest.description}`);
      }
      console.log();

      // Activation events
      const events = manifest.activationEvents ?? [];
      console.log(
        `${pc.cyan("Activation Events:")} ${events.length > 0 ? events.join(", ") : pc.dim("(none)")}`,
      );

      // Entry points
      if (manifest.main) {
        console.log(`${pc.cyan("Main Entry:")} ${manifest.main}`);
      }
      if (manifest.browser) {
        console.log(`${pc.cyan("Browser Entry:")} ${manifest.browser}`);
      }

      // Contributions summary
      const contributes = manifest.contributes ?? {};
      const contributionTypes = Object.keys(contributes).filter((k) => {
        const val = contributes[k];
        return Array.isArray(val) ? val.length > 0 : val !== undefined;
      });
      if (contributionTypes.length > 0) {
        console.log(`${pc.cyan("Contributes:")} ${contributionTypes.join(", ")}`);
      }

      // Dependencies
      const deps = manifest["extensionDependencies"] as string[] | undefined;
      if (deps && deps.length > 0) {
        console.log(`${pc.cyan("Extension Dependencies:")} ${deps.join(", ")}`);
      }

      console.log();
      console.log(`${pc.cyan("Files:")} ${contents.files.size}`);
      const totalSize = [...contents.files.values()].reduce((sum, buf) => sum + buf.length, 0);
      console.log(`${pc.cyan("Total Size:")} ${formatBytes(totalSize)}`);
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function printTextReport(result: ScanResult): void {
  console.log();
  console.log(pc.bold("vsix-audit scan results"));
  console.log(pc.dim("─".repeat(50)));
  console.log();
  console.log(`${pc.cyan("Extension:")} ${result.extension.name} v${result.extension.version}`);
  console.log(`${pc.cyan("Publisher:")} ${result.extension.publisher}`);
  console.log(`${pc.cyan("Scanned:")} ${result.metadata.scannedAt}`);
  console.log();

  // Print inventory of checks performed
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

  if (result.findings.length === 0) {
    console.log(pc.green("✓ No security issues found"));
    return;
  }

  console.log(pc.yellow(`Found ${result.findings.length} issue(s):`));
  console.log();

  for (const finding of result.findings) {
    const severityColor = {
      critical: pc.red,
      high: pc.red,
      medium: pc.yellow,
      low: pc.blue,
    }[finding.severity];

    console.log(`  ${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
    console.log(`  ${pc.dim(finding.description)}`);
    if (finding.location) {
      console.log(
        `  ${pc.dim(`at ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`)}`,
      );
    }
    console.log();
  }
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: object[];
}

function toSarif(result: ScanResult): SarifReport {
  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "vsix-audit",
            version: "0.1.0",
            informationUri: "https://github.com/trailofbits/vsix-audit",
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: f.severity === "critical" || f.severity === "high" ? "error" : "warning",
          message: { text: f.description },
          locations: f.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.location.file },
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

function formatFindingSummary(findings: Array<{ severity: Severity }>): string {
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

function printBatchSummary(batch: BatchScanResult): void {
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
    for (const r of withFindings) {
      const summary = formatFindingSummary(r.findings);
      console.log(`  - ${r.extension.name} v${r.extension.version}`);
      console.log(`    ${summary}`);
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
