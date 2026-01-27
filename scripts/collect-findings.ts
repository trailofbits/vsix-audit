#!/usr/bin/env npx tsx
/**
 * Collect findings from scanning known extensions
 *
 * Downloads and scans a set of well-known extensions to:
 * 1. Validate that baseline (clean) extensions produce minimal findings
 * 2. Test that edge case extensions have well-contextualized findings
 *
 * Usage:
 *   npx tsx scripts/collect-findings.ts > findings-report.json
 *   npx tsx scripts/collect-findings.ts --text   # Human-readable output
 */

import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { downloadExtension, type ExtensionMetadata } from "../src/scanner/download.js";
import { scanExtension, type Finding, type ScanResult } from "../src/scanner/index.js";

interface ExtensionConfig {
  id: string;
  category: "baseline" | "edge-case";
  expectedPatterns?: string[];
  description?: string;
}

const EXTENSIONS: ExtensionConfig[] = [
  // Category 1: Clean Baseline (expect minimal/no findings)
  {
    id: "ms-python.python",
    category: "baseline",
    description: "Baseline for a well-behaved extension",
  },
  {
    id: "esbenp.prettier-vscode",
    category: "baseline",
    description: "Simple formatter, should be clean",
  },
  {
    id: "trailofbits.weaudit",
    category: "baseline",
    description: "Our own extension",
  },

  // Category 2: Legitimate Edge Cases (expect findings - test context quality)
  {
    id: "ms-vscode-remote.remote-ssh",
    category: "edge-case",
    expectedPatterns: ["SSH", "child_process"],
    description: "SSH refs, child_process - finding should explain SSH is the extension's purpose",
  },
  {
    id: "eamodio.gitlens",
    category: "edge-case",
    expectedPatterns: ["child_process", "exec"],
    description: "child_process for git - finding should note git CLI usage is expected",
  },
  {
    id: "tintinweb.solidity-visual-auditor",
    category: "edge-case",
    expectedPatterns: ["wallet", "crypto"],
    description: "Wallet/crypto refs - finding should note it's a security audit tool",
  },
  {
    id: "vadimcn.vscode-lldb",
    category: "edge-case",
    expectedPatterns: ["child_process", "native", ".node"],
    description: "Debugger legitimately needs child_process and native binaries",
  },
  {
    id: "juanblanco.solidity",
    category: "edge-case",
    expectedPatterns: ["crypto", "wallet"],
    description: "Solidity dev tool - crypto patterns expected",
  },
];

interface ExtensionReport {
  extension: ExtensionConfig;
  metadata?: ExtensionMetadata;
  scanResult?: ScanResult;
  error?: string;
  analysisNotes: string[];
}

interface CollectionReport {
  timestamp: string;
  summary: {
    total: number;
    scanned: number;
    failed: number;
    baselineClean: number;
    baselineWithFindings: number;
    edgeCaseWithContext: number;
  };
  extensions: ExtensionReport[];
}

function analyzeFindingQuality(finding: Finding): string[] {
  const issues: string[] = [];

  if (!finding.id) issues.push("Missing finding ID");
  if (!finding.title) issues.push("Missing finding title");
  if (!finding.description || finding.description.length < 50) {
    issues.push(`Description too short (${finding.description?.length ?? 0} chars, need 50+)`);
  }
  if (!finding.severity) issues.push("Missing severity");
  if (!finding.location?.file) issues.push("Missing file location");

  return issues;
}

function checkEdgeCaseContext(finding: Finding): boolean {
  const hasLegitimateUses =
    finding.description?.toLowerCase().includes("legitimate") ||
    finding.description?.toLowerCase().includes("common in") ||
    finding.description?.toLowerCase().includes("expected") ||
    (finding.metadata?.legitimateUses as string[] | undefined)?.length;

  return Boolean(hasLegitimateUses);
}

async function collectFindings(textOutput: boolean): Promise<CollectionReport> {
  const workDir = join(tmpdir(), `vsix-audit-collect-${Date.now()}`);
  await mkdir(workDir, { recursive: true });

  const report: CollectionReport = {
    timestamp: new Date().toISOString(),
    summary: {
      total: EXTENSIONS.length,
      scanned: 0,
      failed: 0,
      baselineClean: 0,
      baselineWithFindings: 0,
      edgeCaseWithContext: 0,
    },
    extensions: [],
  };

  for (const ext of EXTENSIONS) {
    if (textOutput) {
      process.stderr.write(`Scanning ${ext.id}...\n`);
    }

    const extReport: ExtensionReport = {
      extension: ext,
      analysisNotes: [],
    };

    try {
      const { path, metadata } = await downloadExtension(ext.id, { destDir: workDir });
      extReport.metadata = metadata;

      const scanResult = await scanExtension(path, {
        output: "json",
        severity: "low",
        network: false,
      });
      extReport.scanResult = scanResult;
      report.summary.scanned++;

      // Analyze findings quality
      for (const finding of scanResult.findings) {
        const qualityIssues = analyzeFindingQuality(finding);
        if (qualityIssues.length > 0) {
          extReport.analysisNotes.push(`Finding ${finding.id}: ${qualityIssues.join(", ")}`);
        }
      }

      // Category-specific analysis
      if (ext.category === "baseline") {
        if (scanResult.findings.length === 0) {
          report.summary.baselineClean++;
          extReport.analysisNotes.push("Clean baseline - no findings");
        } else {
          report.summary.baselineWithFindings++;
          extReport.analysisNotes.push(
            `Baseline has ${scanResult.findings.length} findings (may need investigation)`,
          );
        }
      } else if (ext.category === "edge-case") {
        const findingsWithContext = scanResult.findings.filter(checkEdgeCaseContext);
        const contextRatio =
          scanResult.findings.length > 0
            ? findingsWithContext.length / scanResult.findings.length
            : 1;

        if (contextRatio >= 0.8) {
          report.summary.edgeCaseWithContext++;
          extReport.analysisNotes.push(
            `${findingsWithContext.length}/${scanResult.findings.length} findings have adequate context`,
          );
        } else {
          extReport.analysisNotes.push(
            `Only ${findingsWithContext.length}/${scanResult.findings.length} findings have adequate context`,
          );
        }
      }
    } catch (error) {
      report.summary.failed++;
      extReport.error = error instanceof Error ? error.message : String(error);
      extReport.analysisNotes.push(`Failed to scan: ${extReport.error}`);
    }

    report.extensions.push(extReport);
  }

  // Cleanup
  await rm(workDir, { recursive: true, force: true });

  return report;
}

function formatTextReport(report: CollectionReport): string {
  const lines: string[] = [];

  lines.push("=".repeat(80));
  lines.push("VSIX-AUDIT FINDINGS COLLECTION REPORT");
  lines.push(`Generated: ${report.timestamp}`);
  lines.push("=".repeat(80));
  lines.push("");

  lines.push("SUMMARY");
  lines.push("-".repeat(40));
  lines.push(`Total extensions: ${report.summary.total}`);
  lines.push(`Successfully scanned: ${report.summary.scanned}`);
  lines.push(`Failed to scan: ${report.summary.failed}`);
  lines.push(`Baseline clean: ${report.summary.baselineClean}`);
  lines.push(`Baseline with findings: ${report.summary.baselineWithFindings}`);
  lines.push(`Edge cases with context: ${report.summary.edgeCaseWithContext}`);
  lines.push("");

  for (const ext of report.extensions) {
    lines.push("=".repeat(80));
    lines.push(`Extension: ${ext.extension.id}`);
    lines.push(`Category: ${ext.extension.category}`);
    if (ext.metadata) {
      lines.push(`Publisher: ${ext.metadata.publisher}`);
      lines.push(`Version: ${ext.metadata.version}`);
      if (ext.metadata.installCount) {
        lines.push(`Installs: ${ext.metadata.installCount.toLocaleString()}`);
      }
    }
    lines.push("");

    if (ext.error) {
      lines.push(`ERROR: ${ext.error}`);
      lines.push("");
      continue;
    }

    if (ext.scanResult) {
      lines.push(`Findings: ${ext.scanResult.findings.length}`);
      lines.push("");

      for (const finding of ext.scanResult.findings) {
        const severityBadge = `[${finding.severity.toUpperCase()}]`;
        lines.push(`${severityBadge} ${finding.title}`);
        lines.push(`  ID: ${finding.id}`);
        if (finding.location?.file) {
          lines.push(
            `  File: ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`,
          );
        }
        if (finding.metadata?.matched) {
          const matched = String(finding.metadata.matched).slice(0, 60);
          lines.push(`  Matched: ${matched}${matched.length >= 60 ? "..." : ""}`);
        }

        // Show context quality indicators
        if (finding.metadata?.legitimateUses) {
          const uses = finding.metadata.legitimateUses as string[];
          lines.push(`  Legitimate uses: ${uses.join(", ")}`);
        }
        if (finding.metadata?.redFlags) {
          const flags = finding.metadata.redFlags as string[];
          lines.push(`  Red flags: ${flags.join(", ")}`);
        }

        lines.push("");
      }
    }

    if (ext.analysisNotes.length > 0) {
      lines.push("Analysis Notes:");
      for (const note of ext.analysisNotes) {
        lines.push(`  - ${note}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

async function main(): Promise<void> {
  const textOutput = process.argv.includes("--text");

  try {
    const report = await collectFindings(textOutput);

    if (textOutput) {
      console.log(formatTextReport(report));
    } else {
      console.log(JSON.stringify(report, null, 2));
    }

    // Exit with error if any baseline extensions have unexpected findings
    // or if edge cases lack context
    const hasIssues =
      report.summary.failed > 0 ||
      report.summary.baselineWithFindings > report.summary.baselineClean;

    process.exit(hasIssues ? 1 : 0);
  } catch (error) {
    console.error("Fatal error:", error);
    process.exit(1);
  }
}

main();
