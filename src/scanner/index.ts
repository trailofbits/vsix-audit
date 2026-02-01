import { stat } from "node:fs/promises";
import { checkAST } from "./checks/ast.js";
import { checkIocs } from "./checks/ioc.js";
import { checkObfuscation } from "./checks/obfuscation.js";
import { checkPackage } from "./checks/package.js";
import {
  checkYara,
  DEFAULT_YARA_RULES_DIR,
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
import { loadExtension } from "./vsix.js";

export const MODULE_NAMES = ["package", "obfuscation", "ast", "ioc", "yara"] as const;
export type ModuleName = (typeof MODULE_NAMES)[number];

export type {
  BatchScanResult,
  CheckSummary,
  Finding,
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
  const yaraRules = yaraAvailable ? await listYaraRules(DEFAULT_YARA_RULES_DIR) : [];

  // Count files by type for inventory
  const codeFileCount = countScannableFiles(contents, SCANNABLE_EXTENSIONS_PATTERN);
  const textFileCount = countScannableFiles(contents, SCANNABLE_EXTENSIONS_UNICODE);

  // Package check (blocklist + manifest + dependencies)
  if (shouldRunModule("package", options)) {
    const moduleStart = performance.now();
    findings.push(...checkPackage(contents, zooData));
    timings.package = performance.now() - moduleStart;
    inventory.push({
      name: "Package",
      enabled: true,
      description: "Blocklist, manifest analysis, npm dependencies, lifecycle scripts",
    });
  }

  // Obfuscation check (entropy + Unicode hiding)
  if (shouldRunModule("obfuscation", options)) {
    const moduleStart = performance.now();
    findings.push(...checkObfuscation(contents));
    timings.obfuscation = performance.now() - moduleStart;
    inventory.push({
      name: "Obfuscation",
      enabled: true,
      description: `Entropy and Unicode analysis across ${textFileCount} files`,
      rulesApplied: 8,
      filesExamined: textFileCount,
    });
  }

  // AST analysis
  if (shouldRunModule("ast", options)) {
    const moduleStart = performance.now();
    findings.push(...checkAST(contents));
    timings.ast = performance.now() - moduleStart;
    inventory.push({
      name: "AST",
      enabled: true,
      description: `Structural code analysis across ${codeFileCount} code files`,
      rulesApplied: 7,
      filesExamined: codeFileCount,
    });
  }

  // IOC check
  if (shouldRunModule("ioc", options)) {
    const moduleStart = performance.now();
    findings.push(...checkIocs(contents, zooData));
    timings.ioc = performance.now() - moduleStart;
    inventory.push({
      name: "IOC",
      enabled: true,
      description: "Hashes, domains, IPs against threat intel",
    });
  }

  // YARA check
  if (shouldRunModule("yara", options)) {
    if (yaraAvailable) {
      const moduleStart = performance.now();
      findings.push(...(await checkYara(contents)));
      timings.yara = performance.now() - moduleStart;
      inventory.push({
        name: "YARA",
        enabled: true,
        description: `${yaraRules.length} rules against all files`,
        rulesApplied: yaraRules.length,
        filesExamined: contents.files.size,
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
