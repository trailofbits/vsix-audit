import { stat } from "node:fs/promises";
import { checkAST } from "./checks/ast.js";
import { checkBehavioral } from "./checks/behavioral.js";
import { checkBlocklist } from "./checks/blocklist.js";
import { checkDataFlow } from "./checks/dataflow.js";
import { checkDependencies } from "./checks/dependencies.js";
import { checkIocs } from "./checks/ioc.js";
import { checkManifest } from "./checks/manifest.js";
import { checkObfuscation } from "./checks/obfuscation.js";
import { checkAllPatterns } from "./checks/patterns.js";
import { checkUnicode } from "./checks/unicode.js";
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
  ScanOptions,
  ScanResult,
  Severity,
  VsixContents,
} from "./types.js";
import { loadExtension } from "./vsix.js";

export type { BatchScanResult, CheckSummary, Finding, ScanOptions, ScanResult, Severity };
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

export async function scanExtension(target: string, options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();

  const targetExists = await stat(target).catch(() => null);
  if (!targetExists) {
    throw new Error(`Target not found: ${target}`);
  }

  const [contents, zooData] = await Promise.all([loadExtension(target), loadZooData()]);

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

  // Blocklist check
  findings.push(...checkBlocklist(manifest, zooData.blocklist));
  inventory.push({
    name: "Blocklist",
    enabled: true,
    description: "Extension ID not in malware blocklist",
  });

  // Manifest check
  findings.push(...checkManifest(manifest));
  inventory.push({
    name: "Manifest",
    enabled: true,
    description: "Activation events, entry points, dependencies",
  });

  // Pattern check
  findings.push(...checkAllPatterns(contents));
  inventory.push({
    name: "Patterns",
    enabled: true,
    description: `17 rules across ${codeFileCount} code files`,
    rulesApplied: 17,
    filesExamined: codeFileCount,
  });

  // Obfuscation check (new)
  findings.push(...checkObfuscation(contents));
  inventory.push({
    name: "Obfuscation",
    enabled: true,
    description: `Entropy analysis and obfuscation patterns across ${codeFileCount} code files`,
    rulesApplied: 9,
    filesExamined: codeFileCount,
  });

  // AST analysis (new)
  findings.push(...checkAST(contents));
  inventory.push({
    name: "AST",
    enabled: true,
    description: `Structural code analysis across ${codeFileCount} code files`,
    rulesApplied: 7,
    filesExamined: codeFileCount,
  });

  // Data flow analysis (new)
  findings.push(...checkDataFlow(contents));
  inventory.push({
    name: "DataFlow",
    enabled: true,
    description: `Source-to-sink tracking across ${codeFileCount} code files`,
    rulesApplied: 9,
    filesExamined: codeFileCount,
  });

  // Behavioral signatures (new)
  findings.push(...checkBehavioral(contents));
  inventory.push({
    name: "Behavioral",
    enabled: true,
    description: `Multi-stage attack patterns across ${codeFileCount} code files`,
    rulesApplied: 8,
    filesExamined: codeFileCount,
  });

  // Unicode check
  findings.push(...checkUnicode(contents));
  inventory.push({
    name: "Unicode",
    enabled: true,
    description: `7 rules across ${textFileCount} text files`,
    rulesApplied: 7,
    filesExamined: textFileCount,
  });

  // IOC check
  findings.push(...checkIocs(contents, zooData));
  inventory.push({
    name: "IOC",
    enabled: true,
    description: "Hashes, domains, IPs against threat intel",
  });

  // Dependencies check
  findings.push(...checkDependencies(contents, zooData));
  inventory.push({
    name: "Dependencies",
    enabled: true,
    description: "package.json scripts and packages",
  });

  // YARA check
  if (yaraAvailable) {
    findings.push(...(await checkYara(contents)));
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

  findings = deduplicateFindings(findings);
  findings = filterBySeverity(findings, options.severity);
  findings = sortFindings(findings);

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
      scanDuration: Date.now() - startTime,
    },
  };
}
