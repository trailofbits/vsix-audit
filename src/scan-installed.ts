import { Option, type Command } from "commander";
import { outputBatchResult } from "#internal/formatters.js";
import { printError, terminalText } from "#internal/terminal.js";
import {
  configureScanOptions,
  batchExitCode,
  parseJobs,
  parseScanOptions,
  type CliScanOptions,
} from "#internal/scan-options.js";
import { scanPaths, summarizeBatch } from "#internal/scanner/batch.js";
import {
  findInstalledExtensions,
  INSTALLED_EDITORS,
  type InstalledEditor,
} from "#internal/scanner/installed.js";

interface InstalledCliOptions extends CliScanOptions {
  editor: InstalledEditor;
  extensionsDir?: string;
  jobs: number;
}

async function scanInstalled(options: InstalledCliOptions, version: string): Promise<number> {
  const scanOptions = parseScanOptions(options);
  const started = Date.now();
  const { paths, errors, ...discovery } = await findInstalledExtensions({
    editor: options.editor,
    ...(options.extensionsDir === undefined ? {} : { extensionsDir: options.extensionsDir }),
  });
  console.error(`Scope: ${terminalText(discovery.scope)}`);
  for (const root of discovery.roots) console.error(`Store: ${terminalText(root)}`);
  for (const error of errors) printError(error.error);
  console.error(`Scanning ${paths.length} installed extension(s).`);
  const scanned = await scanPaths(
    paths,
    scanOptions,
    {
      onResult: (path, result) => {
        result.metadata.sourcePath = path;
      },
    },
    { concurrency: options.jobs },
  );
  const batch = summarizeBatch(
    scanned.results,
    [...errors, ...scanned.errors],
    paths.length + errors.length,
    started,
  );
  batch.discovery = discovery;
  outputBatchResult(batch, scanOptions.output, version);
  return batchExitCode(batch, scanOptions);
}

/** Register local editor-store scanning with the standard scanner controls and reports. */
export function registerInstalledCommand(program: Command, version: string): void {
  const command = configureScanOptions(program.command("scan-installed"))
    .description("Scan extensions installed in local editor stores")
    .allowExcessArguments(false)
    .addOption(
      new Option("--editor <name>", "Editor store to scan")
        .choices([...INSTALLED_EDITORS])
        .default("all"),
    )
    .addOption(
      new Option("--extensions-dir <path>", "Scan a custom extensions directory").conflicts(
        "editor",
      ),
    )
    .addOption(
      new Option("-j, --jobs <n>", "Number of parallel scans").argParser(parseJobs).default(4),
    );
  command.action(async (options: InstalledCliOptions) => {
    try {
      process.exitCode = await scanInstalled(options, version);
    } catch (error) {
      printError(error);
      process.exitCode = 2;
    }
  });
}
