import { existsSync } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { printError, reportJson, terminalText } from "#internal/terminal.js";
import { registerInstalledCommand } from "#internal/scan-installed.js";
import {
  batchExitCode,
  configureScanOptions,
  hasCoverageExitFailure,
  parseJobs,
  parseScanOptions,
  type CliScanOptions as CommonScanOptions,
} from "#internal/scan-options.js";
import {
  formatBytes,
  formatFindingSummary,
  outputBatchResult,
  outputResult,
} from "#internal/formatters.js";
import { clearCache, getCacheDir, getCachedVersions, listCached } from "#internal/scanner/cache.js";
import { extractCapabilities, type Capabilities } from "#internal/scanner/capabilities.js";
import {
  downloadExtension,
  ExtensionNotFoundError,
  parseExtensionId,
  type ParsedExtensionId,
} from "#internal/scanner/download.js";
import { scanDirectory, scanExtension } from "#internal/scanner/index.js";
import { createRepositoryCheck } from "#internal/scanner/checks/repository.js";
import type { RepositoryCheck } from "#internal/scanner/checks/repository.js";
import { summarizeBatch, type BatchScanCallbacks } from "#internal/scanner/batch.js";
import type {
  BatchScanResult,
  Registry,
  ScanOptions,
  ScanResult,
  VsixContents,
} from "#internal/scanner/types.js";
import { loadExtension } from "#internal/scanner/vsix.js";
import { isScannable, JS_EXTENSIONS } from "#internal/scanner/constants.js";

const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json") as {
  version: string;
};

const REGISTRIES: Registry[] = ["marketplace", "openvsx", "cursor"];

interface CliScanOptions extends CommonScanOptions {
  allRegistries?: boolean;
  cache?: boolean;
  force?: boolean;
  recursive?: boolean;
  jobs?: string;
}

interface CliDownloadOptions {
  output?: string;
  cache?: boolean;
  force?: boolean;
}

export type CliTarget =
  | { kind: "path"; path: string }
  | {
      kind: "extension-id";
      extensionId: string;
      unprefixedExtensionId: string;
      parsed: ParsedExtensionId;
    };

interface TargetClassifierOptions {
  exists?: (path: string) => boolean;
}

function hasRegistryPrefix(target: string): boolean {
  return REGISTRIES.some((registry) => target.startsWith(`${registry}:`));
}

function isExplicitLocalPath(target: string): boolean {
  return (
    target.startsWith("/") ||
    target.startsWith("./") ||
    target.startsWith("../") ||
    target.startsWith("~") ||
    /^[A-Za-z]:[\\/]/.test(target) ||
    target.includes("\\")
  );
}

function isRelativePathCandidate(target: string, exists: (path: string) => boolean): boolean {
  return target.includes("/") && (exists(target) || target.toLowerCase().endsWith(".vsix"));
}

function formatUnprefixedExtensionId(parsed: ParsedExtensionId): string {
  const version = parsed.version === undefined ? "" : `@${parsed.version}`;
  return `${parsed.publisher}/${parsed.name}${version}`;
}

export function classifyTarget(target: string, options: TargetClassifierOptions = {}): CliTarget {
  const exists = options.exists ?? existsSync;

  if (
    !hasRegistryPrefix(target) &&
    (isExplicitLocalPath(target) || isRelativePathCandidate(target, exists))
  ) {
    return { kind: "path", path: target };
  }

  try {
    const parsed = parseExtensionId(target);
    return {
      kind: "extension-id",
      extensionId: target,
      unprefixedExtensionId: formatUnprefixedExtensionId(parsed),
      parsed,
    };
  } catch {
    return { kind: "path", path: target };
  }
}

interface ScanContext {
  options: ScanOptions;
  repositoryCheck: RepositoryCheck;
  useCache: boolean;
  forceDownload: boolean;
  statusStream: NodeJS.WriteStream;
  statusLog: (...args: unknown[]) => void;
}

function createScanContext(options: CliScanOptions): ScanContext {
  const scanOptions = parseScanOptions(options);
  const machineOutput = scanOptions.output !== "text";
  return {
    options: scanOptions,
    repositoryCheck: createRepositoryCheck(),
    useCache: options.cache !== false,
    forceDownload: options.force === true,
    statusStream: machineOutput ? process.stderr : process.stdout,
    statusLog: (...args) => {
      if (machineOutput) console.error(...args);
      else console.log(...args);
    },
  };
}

async function scanDownloadedExtension(
  extensionId: string,
  context: ScanContext,
): Promise<ScanResult> {
  const tempDir = context.useCache ? undefined : await mkdtemp(join(tmpdir(), "vsix-audit-scan-"));
  try {
    const downloaded = await downloadExtension(extensionId, {
      useCache: context.useCache,
      forceDownload: context.forceDownload,
      ...(tempDir === undefined ? {} : { destDir: tempDir }),
    });
    const message = downloaded.fromCache === true ? "✓ Using cached" : "✓ Downloaded";
    context.statusLog(pc.green(message), pc.dim(terminalText(downloaded.path)));
    return await scanExtension(downloaded.path, context.options, context.repositoryCheck);
  } finally {
    if (tempDir !== undefined) await rm(tempDir, { recursive: true, force: true });
  }
}

async function scanAllRegistries(
  target: Extract<CliTarget, { kind: "extension-id" }>,
  context: ScanContext,
): Promise<number> {
  const startTime = Date.now();
  const results: ScanResult[] = [];
  const errors: BatchScanResult["errors"] = [];
  const baseId = target.unprefixedExtensionId;
  for (const registry of REGISTRIES) {
    const extensionId = `${registry}:${baseId}`;
    try {
      context.statusLog(pc.cyan(`Downloading from ${registry}:`), terminalText(baseId));
      const result = await scanDownloadedExtension(extensionId, context);
      result.metadata.registry = registry;
      results.push(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const label = error instanceof ExtensionNotFoundError ? "Not found" : "Failed";
      context.statusLog(pc.dim(terminalText(`  ${label} in ${registry}: ${message}`)));
      errors.push({ path: extensionId, error: message });
    }
  }
  const batch = summarizeBatch(results, errors, REGISTRIES.length, startTime);
  outputBatchResult(batch, context.options.output, VERSION);
  return batchExitCode(batch, context.options);
}

function recursiveCallbacks(concurrency: number, context: ScanContext): BatchScanCallbacks {
  const isParallel = concurrency > 1;
  const stream = isParallel ? process.stderr : context.statusStream;
  return {
    onProgress: (completed, total) => {
      if (isParallel) process.stderr.write(`\r[${completed}/${total}] Scanning...`);
    },
    onResult: (_path, result) => {
      stream.write("\r\x1b[K");
      const label = terminalText(`${result.extension.name} v${result.extension.version}`);
      if (result.findings.length === 0) {
        context.statusLog(`[${pc.green("OK")}] ${label}`);
        return;
      }
      const summary = formatFindingSummary(result.findings);
      context.statusLog(
        `[${pc.yellow("WARN")}] ${label} - ${result.findings.length} issue(s) (${summary})`,
      );
    },
    onError: (path, error) => {
      stream.write("\r\x1b[K");
      context.statusLog(
        `[${pc.red("ERROR")}] ${terminalText(basename(path))} - Error: ${terminalText(error)}`,
      );
    },
  };
}

async function scanRecursive(
  target: string,
  options: CliScanOptions,
  context: ScanContext,
): Promise<number> {
  const targetStat = await stat(target);
  if (!targetStat.isDirectory()) {
    throw new Error(`--recursive requires a directory path: ${target}`);
  }
  const concurrency = parseJobs(options.jobs ?? "4");
  context.statusLog(pc.cyan("Scanning directory:"), terminalText(target));
  if (concurrency > 1) {
    context.statusLog(pc.dim(`Parallel mode: ${concurrency} concurrent scans`));
  }
  context.statusLog();
  const batch = await scanDirectory(
    target,
    context.options,
    recursiveCallbacks(concurrency, context),
    { concurrency },
  );
  outputBatchResult(batch, context.options.output, VERSION);
  return batchExitCode(batch, context.options);
}

async function scanSingle(target: CliTarget, context: ScanContext): Promise<number> {
  let result: ScanResult;
  if (target.kind === "extension-id") {
    context.statusLog(pc.cyan("Downloading:"), terminalText(target.extensionId));
    result = await scanDownloadedExtension(target.extensionId, context);
    context.statusLog();
  } else result = await scanExtension(target.path, context.options, context.repositoryCheck);
  outputResult(result, context.options.output, VERSION);
  if (hasCoverageExitFailure(result, context.options)) return 2;
  return result.findings.length > 0 ? 1 : 0;
}

async function runScan(target: string, options: CliScanOptions): Promise<number> {
  const context = createScanContext(options);
  const targetInfo = classifyTarget(target);
  if (options.allRegistries === true && targetInfo.kind === "extension-id") {
    return scanAllRegistries(targetInfo, context);
  }
  if (
    options.jobs !== undefined &&
    options.jobs !== "" &&
    options.jobs !== "4" &&
    !(options.recursive === true)
  ) {
    context.statusLog(pc.yellow("Warning:"), "--jobs is only used with --recursive, ignoring");
  }
  if (options.recursive === true) return scanRecursive(target, options, context);
  return scanSingle(targetInfo, context);
}

export const cli = new Command()
  .name("vsix-audit")
  .description("Security scanner for VS Code extensions")
  .version(VERSION)
  .configureOutput({
    outputError: (message, write) => {
      write(`${terminalText(message.trimEnd())}\n`);
    },
  })
  .exitOverride((error) => process.exit(error.exitCode === 0 ? 0 : 2));

configureScanOptions(
  cli
    .command("scan")
    .description("Scan a VS Code extension for security issues")
    .argument(
      "<target>",
      "Path to .vsix file or extension ID (e.g., publisher.extension or publisher/extension)",
    ),
)
  .option("--all-registries", "Scan from all registries (Marketplace + OpenVSX + Cursor)")
  .option("--no-cache", "Download fresh without reading or writing the cache")
  .option("--force", "Re-download even if cached")
  .option("-r, --recursive", "Recursively scan all .vsix files in a directory")
  .option("-j, --jobs <n>", "Number of parallel scans (default: 4)", "4")
  .action(async (target: string, options: CliScanOptions) => {
    try {
      process.exitCode = await runScan(target, options);
    } catch (error) {
      printError(error);
      process.exitCode = 2;
    }
  });

registerInstalledCommand(cli, VERSION);

cli
  .command("download")
  .description("Download a VS Code extension from the marketplace")
  .argument(
    "<extension-id>",
    "Extension ID (e.g., ms-python.python, ms-python/python, or ms-python.python@2024.1.0)",
  )
  .option("-o, --output <dir>", "Directory to save the downloaded extension")
  .option("--no-cache", "Download fresh without reading or writing the cache")
  .option("--force", "Re-download even if cached")
  .action(async (extensionId: string, options: CliDownloadOptions) => {
    try {
      const useCache = options.cache !== false;
      const forceDownload = options.force === true;

      console.log(pc.cyan("Downloading:"), terminalText(extensionId));

      const downloadOptions = {
        useCache,
        forceDownload,
        ...(options.output !== undefined && options.output !== ""
          ? { destDir: options.output }
          : {}),
      };
      const result = await downloadExtension(extensionId, downloadOptions);

      printDownloadResult(result);
    } catch (error) {
      printError(error);
      process.exit(2);
    }
  });

function printDownloadResult(result: Awaited<ReturnType<typeof downloadExtension>>): void {
  console.log();
  if (result.fromCache === true) {
    console.log(pc.green("✓ Using cached version"));
  } else {
    console.log(pc.green("✓ Downloaded successfully"));
  }
  console.log(pc.dim("─".repeat(50)));
  console.log(
    `${pc.cyan("Name:")} ${terminalText(result.metadata.displayName ?? result.metadata.name)}`,
  );
  console.log(`${pc.cyan("Publisher:")} ${terminalText(result.metadata.publisher)}`);
  console.log(`${pc.cyan("Version:")} ${terminalText(result.metadata.version)}`);
  if (
    result.metadata.installCount !== undefined &&
    result.metadata.installCount !== 0 &&
    !Number.isNaN(result.metadata.installCount)
  ) {
    console.log(`${pc.cyan("Installs:")} ${result.metadata.installCount.toLocaleString()}`);
  }
  console.log(`${pc.cyan("Path:")} ${terminalText(result.path)}`);
}

interface CliInfoOptions {
  verbose?: boolean;
}

cli
  .command("info")
  .description("Display metadata and capabilities of a VS Code extension")
  .argument(
    "<target>",
    "Path to .vsix file, directory, or extension ID (e.g., publisher.extension or publisher/extension)",
  )
  .option("-v, --verbose", "Show detailed evidence for each capability")
  .action(async (target: string, options: CliInfoOptions) => {
    try {
      const targetInfo = classifyTarget(target);
      let infoTarget: string;
      if (targetInfo.kind === "extension-id") {
        console.log(pc.cyan("Downloading:"), terminalText(targetInfo.extensionId));
        const result = await downloadExtension(targetInfo.extensionId);
        infoTarget = result.path;

        if (result.fromCache === true) {
          console.log(pc.green("✓ Using cached"), pc.dim(terminalText(result.path)));
        } else {
          console.log(pc.green("✓ Downloaded"), pc.dim(terminalText(result.path)));
        }
      } else {
        infoTarget = targetInfo.path;
      }

      const contents = await loadExtension(infoTarget);
      const scanResult = await scanExtension(infoTarget, {
        output: "text",
        severity: "low",
      });
      printExtensionInfo(contents, scanResult, options.verbose ?? false);
    } catch (error) {
      printError(error);
      process.exit(2);
    }
  });

function printManifestInfo(manifest: VsixContents["manifest"]): void {
  // Manifest section
  console.log();
  console.log(pc.dim("── Manifest ") + pc.dim("─".repeat(38)));

  // Activation events
  const events = manifest.activationEvents ?? [];
  const activation = events.length > 0 ? terminalText(events.join(", ")) : pc.dim("(none)");
  console.log(`${pc.cyan("Activation:".padEnd(16))}${activation}`);

  // Entry points
  const entryPoints = (["main", "browser"] as const).flatMap((field) => {
    const value = manifest[field];
    return value === undefined || value === "" ? [] : [`${field}: ${value}`];
  });
  if (entryPoints.length > 0) {
    console.log(`${pc.cyan("Entry Points:".padEnd(16))}${terminalText(entryPoints.join(", "))}`);
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
    console.log(
      `${pc.cyan("Contributes:".padEnd(16))}${terminalText(contributionSummary.join(", "))}`,
    );
  }

  // Dependencies
  const deps = manifest.extensionDependencies;
  if (deps && deps.length > 0) {
    console.log(`${pc.cyan("Dependencies:".padEnd(16))}${terminalText(deps.join(", "))}`);
  }
}

function printExtensionInfo(contents: VsixContents, result: ScanResult, verbose: boolean): void {
  const { manifest } = contents;
  console.log();
  console.log(
    pc.bold(
      terminalText(`Extension: ${manifest.displayName ?? manifest.name} v${manifest.version}`),
    ),
  );
  console.log(`${pc.cyan("Publisher:")} ${terminalText(manifest.publisher ?? "(unknown)")}`);
  if (manifest.description !== undefined && manifest.description !== "") {
    console.log(`${pc.dim(terminalText(manifest.description))}`);
  }

  // Capabilities section
  console.log();
  console.log(pc.dim("── Capabilities ") + pc.dim("─".repeat(34)));
  printCapabilities(extractCapabilities(result), verbose);
  for (const warning of result.metadata.coverage.warnings) {
    console.log(pc.yellow(`Coverage: ${terminalText(warning)}`));
  }

  printManifestInfo(manifest);

  // Stats section
  console.log();
  console.log(pc.dim("── Stats ") + pc.dim("─".repeat(41)));

  const codeFileCount = [...contents.files.keys()].filter((filename) =>
    isScannable(filename, JS_EXTENSIONS),
  ).length;
  console.log(`${pc.cyan("Files:".padEnd(16))}${contents.files.size} (${codeFileCount} code)`);

  const totalSize = [...contents.files.values()].reduce((sum, buf) => sum + buf.length, 0);
  console.log(`${pc.cyan("Size:".padEnd(16))}${formatBytes(totalSize)}`);
  console.log();
}

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
    const summary = cap.detected
      ? terminalText(cap.summary.join(", "))
      : pc.dim("No source observations");
    console.log(`${label.padEnd(16)}${icon} ${summary}`);

    if (verbose && cap.detected) printCapabilityEvidence(cap.evidence);
    if (cap.indicators.length > 0) {
      console.log(
        `                  Indicators: ${terminalText(cap.indicators.map((item) => item.title).join(", "))}`,
      );
    }
  }
}

function printCapabilityEvidence(evidence: Capabilities["network"]["evidence"]): void {
  for (const ev of evidence.slice(0, 5)) {
    const loc = `${ev.file}:${ev.line}:${ev.column}`;
    const excerpt = ev.matched.slice(0, 40);
    const matched = excerpt === "" ? "" : pc.dim(` (${terminalText(excerpt)})`);
    console.log(`                  ${pc.dim("└")} ${pc.dim(terminalText(loc))}${matched}`);
  }
  if (evidence.length > 5) {
    console.log(`                  ${pc.dim(`... and ${evidence.length - 5} more`)}`);
  }
}

// Cache subcommand
const cacheCommand = cli.command("cache").description("Manage the extension cache");

cacheCommand
  .command("path")
  .description("Print the cache directory path")
  .action(() => {
    console.log(terminalText(getCacheDir()));
  });

cacheCommand
  .command("list")
  .description("List cached extensions")
  .option("--json", "Output as JSON")
  .action(async (options: { json?: boolean }) => {
    try {
      const extensions = await listCached();

      if (extensions.length === 0) {
        if (options.json === true) {
          console.log("[]");
        } else {
          console.log(pc.dim("Cache is empty"));
        }
        return;
      }

      if (options.json === true) {
        console.log(reportJson(extensions));
        return;
      }

      console.log();
      console.log(pc.bold("Cached Extensions"));
      console.log(pc.dim("─".repeat(70)));

      for (const ext of extensions) {
        const extensionId = `${ext.publisher}.${ext.name}`;
        const cachedDate = ext.cachedAt.toLocaleDateString();
        console.log(
          `  ${pc.cyan(terminalText(extensionId).padEnd(40))} ` +
            `${pc.dim(terminalText(ext.version).padEnd(12))} ` +
            `${pc.dim(formatBytes(ext.size).padEnd(10))} ` +
            `${pc.dim(terminalText(ext.registry).padEnd(12))} ` +
            `${pc.dim(cachedDate)}`,
        );
      }

      console.log();
      const totalSize = extensions.reduce((sum, ext) => sum + ext.size, 0);
      console.log(
        `${pc.cyan("Total:")} ${extensions.length} extensions, ${formatBytes(totalSize)}`,
      );
    } catch (error) {
      printError(error);
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
        if (pattern !== undefined && pattern !== "") {
          console.log(pc.dim(`No extensions matching "${terminalText(pattern)}" found in cache`));
        } else {
          console.log(pc.dim("Cache is already empty"));
        }
      } else {
        console.log(pc.green(`✓ Cleared ${deleted} extension(s) from cache`));
      }
    } catch (error) {
      printError(error);
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
        console.log(pc.dim(`No cached versions of ${terminalText(extensionId)}`));
        return;
      }

      console.log();
      console.log(pc.bold(`Cached versions of ${terminalText(extensionId)}`));
      console.log(pc.dim("─".repeat(50)));

      for (const ext of versions) {
        const cachedDate = ext.cachedAt.toLocaleDateString();
        console.log(
          `  ${pc.cyan(terminalText(ext.version).padEnd(15))} ` +
            `${pc.dim(terminalText(ext.registry).padEnd(12))} ` +
            `${pc.dim(formatBytes(ext.size).padEnd(10))} ` +
            `${pc.dim(cachedDate)}`,
        );
      }

      console.log();
    } catch (error) {
      printError(error);
      process.exit(2);
    }
  });
