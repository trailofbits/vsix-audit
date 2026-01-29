import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { downloadExtension, parseExtensionId } from "./scanner/download.js";
import { scanExtension } from "./scanner/index.js";
import type { ScanOptions, ScanResult } from "./scanner/types.js";
import { loadExtension } from "./scanner/vsix.js";

/**
 * Check if a target looks like an extension ID vs a local path
 */
function isExtensionId(target: string): boolean {
  // Local paths: start with /, ./, ~, or contain path separators
  if (target.startsWith("/") || target.startsWith("./") || target.startsWith("~")) {
    return false;
  }
  if (target.includes("/") || target.includes("\\")) {
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
  .action(async (target: string, options: ScanOptions) => {
    let scanTarget = target;
    let tempDir: string | undefined;

    async function cleanup(): Promise<void> {
      if (tempDir) {
        await rm(tempDir, { recursive: true, force: true }).catch(() => {});
      }
    }

    try {
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

function toSarif(result: ScanResult): object {
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
