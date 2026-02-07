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
  Finding,
  ModuleTimings,
  ScanOptions,
  ScanResult,
  Severity,
  VsixContents,
} from "./types.js";
import { MODULE_NAMES } from "./types.js";
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

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.id}:${finding.location?.file ?? ""}:${finding.location?.line ?? ""}`;
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

export async function scanExtension(target: string, options: ScanOptions): Promise<ScanResult> {
  const startTime = performance.now();
  const timings: ModuleTimings = { load: 0, total: 0 };

  const targetExists = await stat(target).catch(() => null);
  if (!targetExists) {
    throw new Error(`Target not found: ${target}`);
  }

  const loadStart = performance.now();
  const [contents, zooData] = await Promise.all([loadExtension(target), loadZooData()]);
  timings.load = performance.now() - loadStart;

  const { manifest } = contents;
  const extensionId = `${manifest.publisher}.${manifest.name}`;

  let findings: Finding[] = [];
  const inventory: CheckSummary[] = [];

  // Check YARA availability upfront
  const yaraAvailable = await isYaraAvailable();
  const yaraRulesDir = await getDefaultYaraRulesDir();
  const yaraRules = yaraAvailable ? await listYaraRules(yaraRulesDir) : [];

  // Initialize per-scan caches
  contents.cache = new Map();

  // Pre-compute string contents to avoid redundant conversions
  const stringContents = new Map<string, string>();
  for (const [filename, buffer] of contents.files) {
    if (isScannable(filename, SCANNABLE_EXTENSIONS_UNICODE)) {
      stringContents.set(filename, buffer.toString("utf8"));
    }
  }
  contents.stringContents = stringContents;

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

  if (shouldRunModule("yara", options)) {
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
      ...(options.profile ? { timings } : {}),
    },
  };
}
