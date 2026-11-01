import { Option, type Command } from "commander";
import { outputBatchResult } from "#internal/formatters.js";
import {
  configureScanOptions,
  batchExitCode,
  parseJobs,
  parseScanOptions,
  type CliScanOptions,
} from "#internal/scan-options.js";
import { scanPaths } from "#internal/scanner/batch.js";
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
  const paths = await findInstalledExtensions({
    editor: options.editor,
    ...(options.extensionsDir === undefined ? {} : { extensionsDir: options.extensionsDir }),
  });
  console.error(`Scanning ${paths.length} installed extension(s).`);
  const batch = await scanPaths(
    paths,
    scanOptions,
    {
      onResult: (path, result) => {
        result.metadata.sourcePath = path;
      },
    },
    { concurrency: options.jobs },
  );
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
      console.error("Error:", error instanceof Error ? error.message : String(error));
      process.exitCode = 2;
    }
  });
}
