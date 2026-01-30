import { Command } from "commander";
import pc from "picocolors";
import { clearCache, getCacheDir, getCachedVersions, listCached } from "./scanner/cache.js";
import { extractCapabilities, type Capabilities } from "./scanner/capabilities.js";
import { downloadExtension, parseExtensionId } from "./scanner/download.js";
import { scanExtension } from "./scanner/index.js";
import type { Registry, ScanOptions, ScanResult } from "./scanner/types.js";
import { loadExtension } from "./scanner/vsix.js";

const REGISTRIES: Registry[] = ["marketplace", "openvsx", "cursor"];

interface CliScanOptions extends ScanOptions {
  allRegistries?: boolean;
  noCache?: boolean;
  force?: boolean;
}

interface CliDownloadOptions {
  output?: string;
  noCache?: boolean;
  force?: boolean;
}

/**
 * Strip registry prefix from an extension ID for path-checking purposes
 */
function stripRegistryPrefix(target: string): string {
  if (target.startsWith("openvsx:")) return target.slice(8);
  if (target.startsWith("marketplace:")) return target.slice(12);
  if (target.startsWith("cursor:")) return target.slice(7);
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
  .option("--all-registries", "Scan from all registries (Marketplace + OpenVSX + Cursor)")
  .option("--no-cache", "Bypass cache, download fresh")
  .option("--force", "Re-download even if cached")
  .action(async (target: string, options: CliScanOptions) => {
    try {
      const useCache = options.noCache !== true;
      const forceDownload = options.force === true;

      // Handle --all-registries mode for extension IDs
      if (options.allRegistries && isExtensionId(target)) {
        const results: ScanResult[] = [];
        const baseId = stripRegistryPrefix(target);

        for (const registry of REGISTRIES) {
          const prefixedId = `${registry}:${baseId}`;
          try {
            console.log(pc.cyan(`Downloading from ${registry}:`), baseId);
            const downloaded = await downloadExtension(prefixedId, {
              useCache,
              forceDownload,
            });

            if (downloaded.fromCache) {
              console.log(pc.green("✓ Using cached"), pc.dim(downloaded.path));
            } else {
              console.log(pc.green("✓ Downloaded"), pc.dim(downloaded.path));
            }

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

        const hasFindings = results.some((r) => r.findings.length > 0);
        process.exit(hasFindings ? 1 : 0);
        return;
      }

      // Standard single-registry scan
      let scanTarget = target;
      if (isExtensionId(target)) {
        console.log(pc.cyan("Downloading:"), target);
        const result = await downloadExtension(target, {
          useCache,
          forceDownload,
        });
        scanTarget = result.path;

        if (result.fromCache) {
          console.log(pc.green("✓ Using cached"), pc.dim(result.path));
        } else {
          console.log(pc.green("✓ Downloaded"), pc.dim(result.path));
        }
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
      process.exit(result.findings.length > 0 ? 1 : 0);
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cli
  .command("download")
  .description("Download a VS Code extension from the marketplace")
  .argument("<extension-id>", "Extension ID (e.g., ms-python.python or ms-python.python@2024.1.0)")
  .option("-o, --output <dir>", "Also copy to this directory (in addition to cache)")
  .option("--no-cache", "Bypass cache, download fresh")
  .option("--force", "Re-download even if cached")
  .action(async (extensionId: string, options: CliDownloadOptions) => {
    try {
      const useCache = options.noCache !== true;
      const forceDownload = options.force === true;

      console.log(pc.cyan("Downloading:"), extensionId);

      const downloadOptions = {
        useCache,
        forceDownload,
        ...(options.output ? { destDir: options.output } : {}),
      };
      const result = await downloadExtension(extensionId, downloadOptions);

      console.log();
      if (result.fromCache) {
        console.log(pc.green("✓ Using cached version"));
      } else {
        console.log(pc.green("✓ Downloaded successfully"));
      }
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

interface CliInfoOptions {
  verbose?: boolean;
}

cli
  .command("info")
  .description("Display metadata and capabilities of a VS Code extension")
  .argument(
    "<target>",
    "Path to .vsix file, directory, or extension ID (e.g., publisher.extension)",
  )
  .option("-v, --verbose", "Show detailed evidence for each capability")
  .action(async (target: string, options: CliInfoOptions) => {
    try {
      let infoTarget = target;
      if (isExtensionId(target)) {
        console.log(pc.cyan("Downloading:"), target);
        const result = await downloadExtension(target);
        infoTarget = result.path;

        if (result.fromCache) {
          console.log(pc.green("✓ Using cached"), pc.dim(result.path));
        } else {
          console.log(pc.green("✓ Downloaded"), pc.dim(result.path));
        }
      }

      const contents = await loadExtension(infoTarget);
      const manifest = contents.manifest;

      // Run scanner to get findings for capability extraction
      const scanResult = await scanExtension(infoTarget, {
        output: "text",
        severity: "low",
        network: true,
      });
      const capabilities = extractCapabilities(scanResult.findings);

      console.log();
      console.log(
        pc.bold(`Extension: ${manifest.displayName ?? manifest.name} v${manifest.version}`),
      );
      console.log(`${pc.cyan("Publisher:")} ${manifest.publisher}`);
      if (manifest.description) {
        console.log(`${pc.dim(manifest.description)}`);
      }

      // Capabilities section
      console.log();
      console.log(pc.dim("── Capabilities ") + pc.dim("─".repeat(34)));
      printCapabilities(capabilities, options.verbose ?? false);

      // Manifest section
      console.log();
      console.log(pc.dim("── Manifest ") + pc.dim("─".repeat(38)));

      // Activation events
      const events = manifest.activationEvents ?? [];
      console.log(
        `${pc.cyan("Activation:".padEnd(16))}${events.length > 0 ? events.join(", ") : pc.dim("(none)")}`,
      );

      // Entry points
      const entryPoints: string[] = [];
      if (manifest.main) entryPoints.push(`main: ${manifest.main}`);
      if (manifest.browser) entryPoints.push(`browser: ${manifest.browser}`);
      if (entryPoints.length > 0) {
        console.log(`${pc.cyan("Entry Points:".padEnd(16))}${entryPoints.join(", ")}`);
      }

      // Contributions summary
      const contributes = manifest.contributes ?? {};
      const contributionSummary = Object.entries(contributes)
        .filter(([, val]) => (Array.isArray(val) ? val.length > 0 : val !== undefined))
        .map(([key, val]) => {
          const count = Array.isArray(val) ? val.length : 1;
          return `${key} (${count})`;
        });
      if (contributionSummary.length > 0) {
        console.log(`${pc.cyan("Contributes:".padEnd(16))}${contributionSummary.join(", ")}`);
      }

      // Dependencies
      const deps = manifest["extensionDependencies"] as string[] | undefined;
      if (deps && deps.length > 0) {
        console.log(`${pc.cyan("Dependencies:".padEnd(16))}${deps.join(", ")}`);
      }

      // Stats section
      console.log();
      console.log(pc.dim("── Stats ") + pc.dim("─".repeat(41)));

      const codeExtensions = [".js", ".ts", ".mjs", ".cjs"];
      const codeFileCount = [...contents.files.keys()].filter((f) =>
        codeExtensions.some((ext) => f.endsWith(ext)),
      ).length;
      console.log(`${pc.cyan("Files:".padEnd(16))}${contents.files.size} (${codeFileCount} code)`);

      const totalSize = [...contents.files.values()].reduce((sum, buf) => sum + buf.length, 0);
      console.log(`${pc.cyan("Size:".padEnd(16))}${formatBytes(totalSize)}`);
      console.log();
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

function printCapabilities(capabilities: Capabilities, verbose: boolean): void {
  const capEntries: [string, keyof Capabilities][] = [
    ["Network", "network"],
    ["Execution", "execution"],
    ["File Access", "fileAccess"],
    ["Credentials", "credentials"],
    ["Obfuscation", "obfuscation"],
  ];

  for (const [label, key] of capEntries) {
    const cap = capabilities[key];
    const icon = cap.detected ? pc.green("✓") : pc.dim("✗");
    const summary = cap.detected ? cap.summary.join(", ") : pc.dim("None detected");
    console.log(`${label.padEnd(16)}${icon} ${summary}`);

    if (verbose && cap.detected && cap.evidence.length > 0) {
      for (const ev of cap.evidence.slice(0, 5)) {
        const loc = ev.line ? `${ev.file}:${ev.line}` : ev.file;
        const matched = ev.matched ? pc.dim(` (${ev.matched.slice(0, 40)})`) : "";
        console.log(`                  ${pc.dim("└")} ${pc.dim(loc)}${matched}`);
      }
      if (cap.evidence.length > 5) {
        console.log(`                  ${pc.dim(`... and ${cap.evidence.length - 5} more`)}`);
      }
    }
  }
}

// Cache subcommand
const cacheCommand = cli.command("cache").description("Manage the extension cache");

cacheCommand
  .command("path")
  .description("Print the cache directory path")
  .action(() => {
    console.log(getCacheDir());
  });

cacheCommand
  .command("list")
  .description("List cached extensions")
  .option("--json", "Output as JSON")
  .action(async (options: { json?: boolean }) => {
    try {
      const extensions = await listCached();

      if (extensions.length === 0) {
        if (options.json) {
          console.log("[]");
        } else {
          console.log(pc.dim("Cache is empty"));
        }
        return;
      }

      if (options.json) {
        console.log(JSON.stringify(extensions, null, 2));
        return;
      }

      console.log();
      console.log(pc.bold("Cached Extensions"));
      console.log(pc.dim("─".repeat(70)));

      for (const ext of extensions) {
        const extensionId = `${ext.publisher}.${ext.name}`;
        const cachedDate = ext.cachedAt.toLocaleDateString();
        console.log(
          `  ${pc.cyan(extensionId.padEnd(40))} ` +
            `${pc.dim(ext.version.padEnd(12))} ` +
            `${pc.dim(formatBytes(ext.size).padEnd(10))} ` +
            `${pc.dim(ext.registry.padEnd(12))} ` +
            `${pc.dim(cachedDate)}`,
        );
      }

      console.log();
      const totalSize = extensions.reduce((sum, ext) => sum + ext.size, 0);
      console.log(
        `${pc.cyan("Total:")} ${extensions.length} extensions, ${formatBytes(totalSize)}`,
      );
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cacheCommand
  .command("clear")
  .description("Clear cached extensions")
  .argument("[pattern]", "Optional glob pattern (e.g., ms-python.* or *.python)")
  .action(async (pattern?: string) => {
    try {
      const deleted = await clearCache(pattern);

      if (deleted === 0) {
        if (pattern) {
          console.log(pc.dim(`No extensions matching "${pattern}" found in cache`));
        } else {
          console.log(pc.dim("Cache is already empty"));
        }
      } else {
        console.log(pc.green(`✓ Cleared ${deleted} extension(s) from cache`));
      }
    } catch (error) {
      console.error(pc.red("Error:"), error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });

cacheCommand
  .command("info")
  .description("Show cached versions of an extension")
  .argument("<extension-id>", "Extension ID (e.g., ms-python.python)")
  .action(async (extensionId: string) => {
    try {
      const { publisher, name } = parseExtensionId(extensionId);
      const versions = await getCachedVersions(publisher, name);

      if (versions.length === 0) {
        console.log(pc.dim(`No cached versions of ${extensionId}`));
        return;
      }

      console.log();
      console.log(pc.bold(`Cached versions of ${extensionId}`));
      console.log(pc.dim("─".repeat(50)));

      for (const ext of versions) {
        const cachedDate = ext.cachedAt.toLocaleDateString();
        console.log(
          `  ${pc.cyan(ext.version.padEnd(15))} ` +
            `${pc.dim(ext.registry.padEnd(12))} ` +
            `${pc.dim(formatBytes(ext.size).padEnd(10))} ` +
            `${pc.dim(cachedDate)}`,
        );
      }

      console.log();
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
