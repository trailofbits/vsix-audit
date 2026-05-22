import { stat } from "node:fs/promises";
import { checkAST } from "./checks/ast.js";
import { checkIocs } from "./checks/ioc.js";
import { checkObfuscation } from "./checks/obfuscation.js";
import { checkPackage } from "./checks/package.js";
import { checkTelemetry } from "./checks/telemetry.js";
import {
  checkYara,
  getDefaultYaraRulesDir,
  isYaraAvailable,
  listYaraRules,
} from "./checks/yara.js";
import {
  isScannable,
  SCANNABLE_EXTENSIONS_PATTERN,
  SCANNABLE_EXTENSIONS_UNICODE,
} from "./constants.js";
import { loadZooData } from "./loaders/zoo.js";
import type {
  BatchScanResult,
  CheckSummary,
  CoverageMetadata,
  Finding,
  ModuleTimings,
  OutputFormat,
  ScanOptions,
  ScanResult,
  Severity,
  ZooData,
  VsixContents,
} from "./types.js";
import { INTEL_MODES, MODULE_NAMES, OUTPUT_FORMATS, SEVERITIES } from "./types.js";
import type { ModuleName } from "./types.js";
import { loadExtension } from "./vsix.js";

export { MODULE_NAMES };
export type {
  BatchScanResult,
  CheckSummary,
  Finding,
  ModuleName,
  ModuleTimings,
  ScanOptions,
  ScanResult,
  Severity,
};
export type { BatchScanCallbacks, BatchScanOptions } from "./batch.js";
export { findVsixFiles, scanDirectory } from "./batch.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
  const minLevel = SEVERITY_ORDER[minSeverity];
  return findings.filter((f) => SEVERITY_ORDER[f.severity] >= minLevel);
}

const FINGERPRINT_METADATA_KEYS = [
  "sha256",
  "domain",
  "ip",
  "wallet",
  "rule",
  "command",
  "repo",
  "ref",
  "entryName",
  "normalizedPath",
  "matched",
  "codeSnippet",
];

function findingEvidenceFingerprint(finding: Finding): string {
  const metadata = finding.metadata;
  if (!metadata) return "";

  const values: string[] = [];
  for (const key of FINGERPRINT_METADATA_KEYS) {
    const value = metadata[key];
    if (value !== undefined && value !== null) {
      values.push(`${key}=${String(value)}`);
    }
  }

  return values.join("|");
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = [
      finding.id,
      finding.location?.file ?? "",
      finding.location?.line ?? "",
      findingEvidenceFingerprint(finding),
    ].join(":");
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }

  return result;
}

function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (severityDiff !== 0) return severityDiff;
    return a.id.localeCompare(b.id);
  });
}

function countScannableFiles(contents: VsixContents, extensions: Set<string>): number {
  let count = 0;
  for (const filename of contents.files.keys()) {
    if (isScannable(filename, extensions)) {
      count++;
    }
  }
  return count;
}

interface ScanModule {
  name: ModuleName;
  run: () => Finding[] | Promise<Finding[]>;
  inventory: CheckSummary;
}

function shouldRunModule(name: ModuleName, options: ScanOptions): boolean {
  if (!options.modules || options.modules.length === 0) return true;
  return options.modules.includes(name);
}

function isOutputFormat(value: unknown): value is OutputFormat {
  return typeof value === "string" && OUTPUT_FORMATS.includes(value as OutputFormat);
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && SEVERITIES.includes(value as Severity);
}

function isIntelMode(value: unknown): value is NonNullable<ScanOptions["intel"]> {
  return (
    typeof value === "string" && INTEL_MODES.includes(value as NonNullable<ScanOptions["intel"]>)
  );
}

export function validateScanOptions(options: ScanOptions): void {
  if (!isOutputFormat(options.output)) {
    throw new Error(
      `Invalid output format: ${String(options.output)}. Valid formats: ${OUTPUT_FORMATS.join(", ")}`,
    );
  }

  if (!isSeverity(options.severity)) {
    throw new Error(
      `Invalid severity: ${String(options.severity)}. Valid severities: ${SEVERITIES.join(", ")}`,
    );
  }

  if (options.modules) {
    const invalidModules = options.modules.filter(
      (moduleName) => !MODULE_NAMES.includes(moduleName),
    );
    if (invalidModules.length > 0) {
      throw new Error(
        `Invalid module(s): ${invalidModules.join(", ")}. Valid modules: ${MODULE_NAMES.join(", ")}`,
      );
    }
  }

  if (options.intel !== undefined && !isIntelMode(options.intel)) {
    throw new Error(
      `Invalid intel mode: ${String(options.intel)}. Valid modes: ${INTEL_MODES.join(", ")}`,
    );
  }

  if (options.requireYara && options.modules && !options.modules.includes("yara")) {
    throw new Error("--require-yara cannot be used when the module filter excludes yara");
  }
}

function removeThreatIntel(zooData: ZooData): ZooData {
  return {
    ...zooData,
    blocklist: [],
    hashes: new Set(),
    domains: new Set(),
    ips: new Set(),
    maliciousNpmPackages: new Set(),
    maliciousNpmVersions: new Map(),
    wallets: new Set(),
    blockchainAllowlist: new Set(),
    githubC2Accounts: new Set(),
  };
}

function archiveWarningsToFindings(contents: VsixContents): Finding[] {
  return (contents.archiveWarnings ?? []).map((warning) => ({
    id: warning.id,
    title: warning.title,
    description: warning.message,
    severity: warning.severity,
    category: "archive",
    location: {
      file: warning.normalizedPath ?? warning.entryName,
    },
    metadata: {
      entryName: warning.entryName,
      normalizedPath: warning.normalizedPath,
      reason: warning.reason,
    },
  }));
}

function makeCoverageMetadata(
  warnings: string[],
  unavailableModules: ModuleName[],
): CoverageMetadata {
  const metadata: CoverageMetadata = {
    degraded: warnings.length > 0 || unavailableModules.length > 0,
    warnings,
  };
  if (unavailableModules.length > 0) {
    metadata.unavailableModules = unavailableModules;
  }
  return metadata;
}

export async function scanExtension(target: string, options: ScanOptions): Promise<ScanResult> {
  validateScanOptions(options);

  const startTime = performance.now();
  const timings: ModuleTimings = { load: 0, total: 0 };

  const targetExists = await stat(target).catch(() => null);
  if (!targetExists) {
    throw new Error(`Target not found: ${target}`);
  }

  const loadStart = performance.now();
  const [contents, loadedZooData] = await Promise.all([loadExtension(target), loadZooData()]);
  timings.load = performance.now() - loadStart;
  const intelMode = options.intel ?? "local";
  const zooData = intelMode === "none" ? removeThreatIntel(loadedZooData) : loadedZooData;

  const { manifest } = contents;
  const extensionId = `${manifest.publisher}.${manifest.name}`;

  let findings: Finding[] = [];
  const inventory: CheckSummary[] = [];
  const coverageWarnings: string[] = [];
  const unavailableModules: ModuleName[] = [];

  const runYara = shouldRunModule("yara", options);
  const yaraAvailable = runYara ? await isYaraAvailable() : false;
  const yaraRulesDir = runYara && yaraAvailable ? await getDefaultYaraRulesDir() : "";
  const yaraRules = runYara && yaraAvailable ? await listYaraRules(yaraRulesDir) : [];

  // Initialize per-scan caches
  contents.cache = new Map();
  contents.stringContents = new Map();

  const archiveFindings = archiveWarningsToFindings(contents);
  findings.push(...archiveFindings);
  for (const warning of contents.archiveWarnings ?? []) {
    coverageWarnings.push(warning.message);
  }

  // Count files by type for inventory
  const codeFileCount = countScannableFiles(contents, SCANNABLE_EXTENSIONS_PATTERN);
  const textFileCount = countScannableFiles(contents, SCANNABLE_EXTENSIONS_UNICODE);

  // Build module registry
  const modules: ScanModule[] = [];

  if (shouldRunModule("package", options)) {
    modules.push({
      name: "package",
      run: () => checkPackage(contents, zooData),
      inventory: {
        name: "Package",
        enabled: true,
        description: "Blocklist, manifest analysis, " + "npm dependencies, lifecycle scripts",
      },
    });
  }

  if (shouldRunModule("obfuscation", options)) {
    modules.push({
      name: "obfuscation",
      run: () => checkObfuscation(contents),
      inventory: {
        name: "Obfuscation",
        enabled: true,
        description: `Entropy and Unicode analysis ` + `across ${textFileCount} files`,
        rulesApplied: 8,
        filesExamined: textFileCount,
      },
    });
  }

  if (shouldRunModule("ast", options)) {
    modules.push({
      name: "ast",
      run: () => checkAST(contents),
      inventory: {
        name: "AST",
        enabled: true,
        description: `Structural code analysis across ` + `${codeFileCount} code files`,
        rulesApplied: 7,
        filesExamined: codeFileCount,
      },
    });
  }

  if (shouldRunModule("ioc", options)) {
    modules.push({
      name: "ioc",
      run: () => checkIocs(contents, zooData),
      inventory: {
        name: "IOC",
        enabled: true,
        description: "Hashes, domains, IPs against threat intel",
      },
    });
  }

  if (runYara) {
    if (yaraAvailable) {
      modules.push({
        name: "yara",
        run: () => checkYara(contents),
        inventory: {
          name: "YARA",
          enabled: true,
          description: `${yaraRules.length} rules against all files`,
          rulesApplied: yaraRules.length,
          filesExamined: contents.files.size,
        },
      });
    } else {
      coverageWarnings.push("YARA module requested but YARA-X executable 'yr' is not installed");
      unavailableModules.push("yara");
      findings.push({
        id: "YARA_NOT_INSTALLED",
        title: "YARA-X scanner not available",
        description:
          "YARA-X is not installed. Install with 'brew install yara-x' to enable advanced malware detection using signature rules.",
        severity: "low",
        category: "yara",
        metadata: {
          suggestion: "brew install yara-x",
        },
      });
      inventory.push({
        name: "YARA",
        enabled: false,
        description: "Signature-based malware detection",
        skipReason: "yara not installed",
      });
    }
  }

  if (shouldRunModule("telemetry", options)) {
    modules.push({
      name: "telemetry",
      run: () => checkTelemetry(contents, zooData),
      inventory: {
        name: "Telemetry",
        enabled: true,
        description: "Analytics and data collection detection",
        filesExamined: codeFileCount,
      },
    });
  }

  // Execute all modules
  for (const mod of modules) {
    const start = performance.now();
    findings.push(...(await mod.run()));
    timings[mod.name] = performance.now() - start;
    inventory.push(mod.inventory);
  }

  findings = deduplicateFindings(findings);
  findings = filterBySeverity(findings, options.severity);
  findings = sortFindings(findings);

  timings.total = performance.now() - startTime;
  const coverage = makeCoverageMetadata(coverageWarnings, unavailableModules);

  return {
    extension: {
      id: extensionId,
      name: manifest.displayName ?? manifest.name,
      version: manifest.version,
      publisher: manifest.publisher,
    },
    findings,
    inventory,
    metadata: {
      scannedAt: new Date().toISOString(),
      scanDuration: Math.round(timings.total),
      coverage,
      intel: intelMode,
      ...(options.profile ? { timings } : {}),
    },
  };
}
