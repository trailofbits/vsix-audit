import { InvalidArgumentError, type Command } from "commander";
import { MODULE_NAMES, validateScanOptions } from "#internal/scanner/index.js";
import type { IntelMode, ModuleName, ScanOptions, ScanResult } from "#internal/scanner/types.js";

export interface CliScanOptions extends Omit<ScanOptions, "intel"> {
  module?: string;
  threatIntel?: string | false;
}

/** Add the scanner controls shared by single-target and installed-extension scans. */
export function configureScanOptions(command: Command): Command {
  return command
    .option("-o, --output <format>", "Output format (text, json, sarif)", "text")
    .option("-s, --severity <level>", "Minimum severity (low, medium, high, critical)", "low")
    .option("--no-network", "Disable network-based checks")
    .option(
      "-m, --module <names>",
      "Run specific modules (comma-separated: " + MODULE_NAMES.join(",") + ")",
    )
    .option("--threat-intel <mode>", "Threat intelligence mode (local, none)", "local")
    .option("--no-threat-intel", "Disable threat-intelligence datasets, keeping generic detections")
    .option("--profile", "Show detailed timing breakdown for each module")
    .option("--strict", "Exit with an error if scanner coverage is degraded")
    .option("--require-yara", "Exit with an error if YARA scanning cannot run");
}

/** Parse module and intelligence selections, rejecting invalid scanner options. */
export function parseScanOptions(options: CliScanOptions): ScanOptions {
  const modules = options.module?.split(",").map((name) => name.trim());
  if (modules) {
    const invalid = modules.filter((name) => !MODULE_NAMES.includes(name as ModuleName));
    if (invalid.length > 0) {
      throw new Error(
        `Unknown module(s): ${invalid.join(", ")}. Valid modules: ${MODULE_NAMES.join(", ")}`,
      );
    }
  }
  const intel = options.threatIntel === false ? "none" : (options.threatIntel ?? "local");
  const scanOptions: ScanOptions = {
    output: options.output,
    severity: options.severity,
    network: options.network,
    intel: intel as IntelMode,
    profile: options.profile === true,
    strict: options.strict === true,
    requireYara: options.requireYara === true,
    ...(modules ? { modules: modules as ModuleName[] } : {}),
  };
  validateScanOptions(scanOptions);
  return scanOptions;
}

/** Parse a positive decimal worker count without truncating malformed input. */
export function parseJobs(value: string): number {
  const count = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(count) || count < 1) {
    throw new InvalidArgumentError(`--jobs must be a positive safe integer, received '${value}'.`);
  }
  return count;
}

/** Determine whether requested coverage guarantees failed for a completed scan. */
export function hasCoverageExitFailure(result: ScanResult, options: ScanOptions): boolean {
  const coverage = result.metadata.coverage;
  if (!coverage) return false;
  if (options.strict === true && coverage.degraded) return true;
  return options.requireYara === true && coverage.unavailableModules?.includes("yara") === true;
}
