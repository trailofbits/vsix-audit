import { inspect } from "node:util";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { checkIocs } from "#internal/scanner/checks/ioc.js";
import { checkObfuscation } from "#internal/scanner/checks/obfuscation.js";
import {
  checkDependencyHeuristics,
  checkExecutionPatterns,
  checkManifest,
  checkPackageIntel,
} from "#internal/scanner/checks/package.js";
import { checkTelemetry } from "#internal/scanner/checks/telemetry.js";
import { checkYara } from "#internal/scanner/checks/yara.js";
import { createRepositoryCheck } from "#internal/scanner/checks/repository.js";
import type { RepositoryCheck } from "#internal/scanner/checks/repository.js";
import {
  isScannable,
  JS_EXTENSIONS,
  SCANNABLE_EXTENSIONS_PATTERN,
  SCANNABLE_EXTENSIONS_UNICODE,
} from "#internal/scanner/constants.js";
import { loadZooData } from "#internal/scanner/loaders/zoo.js";
import type {
  BatchScanResult,
  CheckSummary,
  CheckResult,
  CoverageMetadata,
  Finding,
  ModuleTimings,
  OutputFormat,
  ScanOptions,
  ScanResult,
  Severity,
  ZooData,
  VsixContents,
  VsixManifest,
} from "#internal/scanner/types.js";
import { INTEL_MODES, MODULE_NAMES, OUTPUT_FORMATS, SEVERITIES } from "#internal/scanner/types.js";
import type { ModuleName } from "#internal/scanner/types.js";
import { extensionId } from "#internal/scanner/utils.js";
import { loadExtension } from "#internal/scanner/vsix.js";

export { MODULE_NAMES };
export type {
  BatchScanResult,
  CheckSummary,
  CheckResult,
  Finding,
  ModuleName,
  ModuleTimings,
  ScanOptions,
  ScanResult,
  Severity,
};
export type { BatchScanCallbacks, BatchScanOptions } from "#internal/scanner/batch.js";
export { findVsixFiles, scanDirectory, scanPaths } from "#internal/scanner/batch.js";

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
  "ruleFile",
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
      const evidence =
        typeof value === "string"
          ? value
          : inspect(value, {
              sorted: true,
              customInspect: false,
              depth: null,
              maxStringLength: null,
              maxArrayLength: null,
            });
      values.push(`${key}=${evidence}`);
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
  run: (
    contents: VsixContents,
    data: ZooData,
    repository: RepositoryCheck,
  ) => CheckResult | Promise<CheckResult>;
  inventory: Omit<CheckSummary, "enabled" | "filesExamined">;
  extensions?: Set<string>;
}

const SCAN_MODULES: readonly ScanModule[] = [
  {
    name: "repository",
    run: (contents, _data, checkRepository) => checkRepository(contents),
    inventory: {
      name: "Repository",
      description: "Opt-in source repository accessibility and empty-repository checks",
    },
  },
  {
    name: "manifest",
    run: (contents) => ({ findings: checkManifest(contents), warnings: [] }),
    inventory: {
      name: "Manifest",
      description: "Activation events, contribution shape, extension permissions",
    },
  },
  {
    name: "execution",
    run: (contents) => ({ findings: checkExecutionPatterns(contents), warnings: [] }),
    extensions: SCANNABLE_EXTENSIONS_PATTERN,
    inventory: {
      name: "Execution",
      description: "Runtime command, task, and startup execution patterns",
    },
  },
  {
    name: "deps",
    run: (contents) => ({ findings: checkDependencyHeuristics(contents), warnings: [] }),
    inventory: { name: "Deps", description: "Dependency typosquatting and npm lifecycle scripts" },
  },
  {
    name: "intel",
    run: (contents, data) => ({ findings: checkPackageIntel(contents, data), warnings: [] }),
    inventory: {
      name: "Intel",
      description: "Blocklist and known malicious dependency intelligence",
    },
  },
  {
    name: "obfuscation",
    run: (contents) => ({ findings: checkObfuscation(contents), warnings: [] }),
    extensions: SCANNABLE_EXTENSIONS_UNICODE,
    inventory: {
      name: "Obfuscation",
      description: "Entropy and Unicode analysis",
      rulesApplied: 8,
    },
  },
  {
    name: "ast",
    run: checkAST,
    extensions: JS_EXTENSIONS,
    inventory: { name: "AST", description: "Structural code analysis", rulesApplied: 7 },
  },
  {
    name: "ioc",
    run: (contents, data) => ({ findings: checkIocs(contents, data), warnings: [] }),
    inventory: { name: "IOC", description: "Hashes, domains, IPs against threat intel" },
  },
  {
    name: "yara",
    run: (contents) => checkYara(contents),
    inventory: { name: "YARA", description: "YARA-X signature matching" },
  },
  {
    name: "telemetry",
    run: (contents, data) => ({ findings: checkTelemetry(contents, data), warnings: [] }),
    extensions: JS_EXTENSIONS,
    inventory: { name: "Telemetry", description: "Analytics and data collection detection" },
  },
];

function shouldRunModule(name: ModuleName, options: ScanOptions): boolean {
  if (
    name === "repository" &&
    options.checkRepository !== true &&
    options.modules?.includes(name) !== true
  ) {
    return false;
  }
  return !options.modules || options.modules.length === 0 || options.modules.includes(name);
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

  if (options.intel !== undefined && !isIntelMode(options.intel)) {
    throw new Error(
      `Invalid intel mode: ${String(options.intel)}. Valid modes: ${INTEL_MODES.join(", ")}`,
    );
  }

  validateModuleOptions(options);
}

function validateModuleOptions(options: ScanOptions): void {
  if (options.modules === undefined || options.modules.length === 0) return;
  const invalid = options.modules.filter((name) => !MODULE_NAMES.includes(name));
  if (invalid.length > 0) {
    throw new Error(
      `Invalid module(s): ${invalid.join(", ")}. Valid modules: ${MODULE_NAMES.join(", ")}`,
    );
  }
  const requirements = [
    { enabled: options.checkRepository, module: "repository", flag: "--check-repository" },
    { enabled: options.requireYara, module: "yara", flag: "--require-yara" },
  ] as const;
  for (const requirement of requirements) {
    if (requirement.enabled === true && !options.modules.includes(requirement.module)) {
      throw new Error(
        `${requirement.flag} cannot be used when the module filter excludes ${requirement.module}`,
      );
    }
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

function moduleInventory(
  module: ScanModule,
  contents: VsixContents,
  result: CheckResult,
): CheckSummary {
  return {
    ...module.inventory,
    enabled: result.warnings.length === 0,
    ...(module.extensions === undefined
      ? {}
      : { filesExamined: countScannableFiles(contents, module.extensions) }),
    ...(result.warnings.length === 0 ? {} : { skipReason: result.warnings.join("; ") }),
  };
}

function extensionMetadata(manifest: VsixManifest): ScanResult["extension"] {
  return {
    id: extensionId(manifest),
    name: manifest.displayName ?? manifest.name,
    version: manifest.version,
    ...(manifest.publisher === undefined ? {} : { publisher: manifest.publisher }),
  };
}

/**
 * Scan an archive or directory, retaining findings and explicit coverage failures.
 *
 * A batch can pass one repository check to share bounded HTTP lookups across extensions.
 */
export async function scanExtension(
  target: string,
  options: ScanOptions,
  repositoryCheck: RepositoryCheck = createRepositoryCheck(),
): Promise<ScanResult> {
  validateScanOptions(options);

  const startTime = performance.now();
  const timings: ModuleTimings = { load: 0, total: 0 };

  const loadStart = performance.now();
  const [contents, loadedZooData] = await Promise.all([loadExtension(target), loadZooData()]);
  timings.load = performance.now() - loadStart;
  const intelMode = options.intel ?? "local";
  const zooData = intelMode === "none" ? removeThreatIntel(loadedZooData) : loadedZooData;

  let findings: Finding[] = [];
  const inventory: CheckSummary[] = [];
  const coverageWarnings: string[] = [];
  const incompleteModules: ModuleName[] = [];

  const archiveFindings = archiveWarningsToFindings(contents);
  findings.push(...archiveFindings);
  for (const warning of contents.archiveWarnings ?? []) {
    coverageWarnings.push(warning.message);
  }

  // Execute all modules
  for (const mod of SCAN_MODULES.filter((module) => shouldRunModule(module.name, options))) {
    const start = performance.now();
    const result = await mod.run(contents, zooData, repositoryCheck);
    findings.push(...result.findings);
    coverageWarnings.push(...result.warnings);
    if (result.warnings.length > 0) incompleteModules.push(mod.name);
    timings[mod.name] = performance.now() - start;
    inventory.push(moduleInventory(mod, contents, result));
  }

  const coverage: CoverageMetadata = {
    degraded: coverageWarnings.length > 0,
    warnings: coverageWarnings,
    incompleteModules,
  };
  findings = deduplicateFindings(findings);
  findings = filterBySeverity(findings, options.severity);
  findings = sortFindings(findings);

  timings.total = performance.now() - startTime;

  return {
    extension: extensionMetadata(contents.manifest),
    findings,
    inventory,
    metadata: {
      scannedAt: new Date().toISOString(),
      scanDuration: Math.round(timings.total),
      coverage,
      intel: intelMode,
      ...(options.profile === true ? { timings } : {}),
    },
  };
}
