import { stat } from "node:fs/promises";
import { checkBlocklist } from "./checks/blocklist.js";
import { checkDependencies } from "./checks/dependencies.js";
import { checkIocs } from "./checks/ioc.js";
import { checkManifest } from "./checks/manifest.js";
import { checkAllPatterns } from "./checks/patterns.js";
import { checkUnicode } from "./checks/unicode.js";
import { checkYara } from "./checks/yara.js";
import { loadZooData } from "./loaders/zoo.js";
import type { Finding, ScanOptions, ScanResult, Severity } from "./types.js";
import { loadExtension } from "./vsix.js";

export type { Finding, ScanOptions, ScanResult, Severity };

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

export async function scanExtension(target: string, options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();

  const targetExists = await stat(target).catch(() => null);
  if (!targetExists) {
    return {
      extension: {
        id: target,
        name: target,
        version: "0.0.0",
        publisher: "unknown",
      },
      findings: [],
      metadata: {
        scannedAt: new Date().toISOString(),
        scanDuration: Date.now() - startTime,
      },
    };
  }

  const [contents, zooData] = await Promise.all([loadExtension(target), loadZooData()]);

  const { manifest } = contents;
  const extensionId = `${manifest.publisher}.${manifest.name}`;

  let findings: Finding[] = [];

  // Core security checks
  findings.push(...checkBlocklist(manifest, zooData.blocklist));
  findings.push(...checkIocs(contents, zooData));
  findings.push(...checkManifest(manifest));
  findings.push(...checkAllPatterns(contents));

  // v2 checks
  findings.push(...checkUnicode(contents));
  findings.push(...checkDependencies(contents, zooData));
  findings.push(...(await checkYara(contents)));

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
    metadata: {
      scannedAt: new Date().toISOString(),
      scanDuration: Date.now() - startTime,
    },
  };
}
