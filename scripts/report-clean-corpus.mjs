#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const defaultManifestPath = join(repoRoot, "test-corpus", "clean", "manifest.json");
const defaultInputDir = join(repoRoot, "test-corpus", "clean");
const scannerPath = join(repoRoot, "dist", "scanner", "index.js");
const cleanCorpusPath = join(repoRoot, "dist", "scanner", "clean-corpus.js");

const SEVERITIES = ["critical", "high", "medium", "low"];

function parseArgs(argv) {
  const options = {
    manifestPath: defaultManifestPath,
    inputDir: defaultInputDir,
    json: false,
    failOnNever: false,
  };

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--manifest") {
      const value = argv[++index];
      if (!value) throw new Error("--manifest requires a path");
      options.manifestPath = resolve(value);
    } else if (arg === "--input") {
      const value = argv[++index];
      if (!value) throw new Error("--input requires a directory");
      options.inputDir = resolve(value);
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--fail-on-never") {
      options.failOnNever = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

async function sha256File(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

function increment(map, key, amount = 1) {
  map[key] = (map[key] ?? 0) + amount;
}

function summarizeFindings(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byId = {};

  for (const finding of findings) {
    increment(bySeverity, finding.severity);
    increment(byId, finding.id);
  }

  return {
    total: findings.length,
    bySeverity,
    byId: Object.fromEntries(Object.entries(byId).sort((a, b) => b[1] - a[1])),
  };
}

function compactFinding(finding) {
  return {
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    file: finding.location?.file,
    line: finding.location?.line,
  };
}

async function loadBuiltModules() {
  if (!existsSync(scannerPath) || !existsSync(cleanCorpusPath)) {
    throw new Error("Built scanner not found. Run npm run build first.");
  }

  const scanner = await import(pathToFileURL(scannerPath).href);
  const cleanCorpus = await import(pathToFileURL(cleanCorpusPath).href);
  return {
    scanExtension: scanner.scanExtension,
    cleanCorpusFilename: cleanCorpus.cleanCorpusFilename,
    isNeverCleanFindingId: cleanCorpus.isNeverCleanFindingId,
    validateCleanCorpusManifest: cleanCorpus.validateCleanCorpusManifest,
  };
}

function formatTextReport(report) {
  const lines = [];
  lines.push("VSIX-AUDIT CLEAN CORPUS FALSE-POSITIVE REPORT");
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push("");
  lines.push(`Scanned: ${report.summary.scanned}/${report.summary.total}`);
  lines.push(`Findings: ${report.summary.findings.total}`);
  lines.push(`Never-in-clean findings: ${report.summary.neverFindings}`);
  lines.push("");

  for (const severity of SEVERITIES) {
    const count = report.summary.findings.bySeverity[severity] ?? 0;
    if (count > 0) lines.push(`${severity}: ${count}`);
  }

  const sortedIds = Object.entries(report.summary.findings.byId);
  if (sortedIds.length > 0) {
    lines.push("");
    lines.push("Finding IDs:");
    for (const [id, count] of sortedIds) {
      lines.push(`  ${id}: ${count}`);
    }
  }

  for (const extension of report.extensions) {
    lines.push("");
    lines.push(`${extension.id}@${extension.version}`);
    if (extension.error) {
      lines.push(`  ERROR: ${extension.error}`);
      continue;
    }
    lines.push(`  findings: ${extension.findings.total}`);
    lines.push(`  never-in-clean: ${extension.neverFindings.length}`);
    for (const finding of extension.neverFindings) {
      const location = finding.file
        ? ` at ${finding.file}${finding.line ? `:${finding.line}` : ""}`
        : "";
      lines.push(`  FAIL ${finding.severity} ${finding.id}${location}`);
    }
  }

  return lines.join("\n");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const { scanExtension, cleanCorpusFilename, isNeverCleanFindingId, validateCleanCorpusManifest } =
    await loadBuiltModules();

  const manifest = validateCleanCorpusManifest(
    JSON.parse(await readFile(options.manifestPath, "utf8")),
  );

  const extensionReports = [];
  const allFindings = [];
  let neverFindingCount = 0;
  let errorCount = 0;

  for (const extension of manifest.extensions) {
    const filename = cleanCorpusFilename(extension);
    const filePath = join(options.inputDir, filename);
    const extensionReport = {
      id: extension.id,
      version: extension.version,
      registry: extension.registry,
      category: extension.category,
      file: filePath,
      findings: { total: 0, bySeverity: {}, byId: {} },
      neverFindings: [],
    };

    try {
      if (!existsSync(filePath)) {
        throw new Error(`missing VSIX artifact; run npm run corpus:download (${filename})`);
      }

      const actualSha = await sha256File(filePath);
      if (actualSha !== extension.sha256) {
        throw new Error(`sha256 mismatch: expected ${extension.sha256}, got ${actualSha}`);
      }

      const result = await scanExtension(filePath, {
        output: "json",
        severity: "low",
        network: false,
        intel: "local",
      });
      const findings = result.findings.map(compactFinding);
      const neverFindings = findings.filter((finding) => isNeverCleanFindingId(finding.id));

      extensionReport.findings = summarizeFindings(findings);
      extensionReport.neverFindings = neverFindings;
      allFindings.push(...findings);
      neverFindingCount += neverFindings.length;
    } catch (error) {
      errorCount++;
      extensionReport.error = error instanceof Error ? error.message : String(error);
    }

    extensionReports.push(extensionReport);
  }

  const report = {
    generatedAt: new Date().toISOString(),
    manifest: options.manifestPath,
    inputDir: options.inputDir,
    summary: {
      total: manifest.extensions.length,
      scanned: manifest.extensions.length - errorCount,
      errors: errorCount,
      neverFindings: neverFindingCount,
      findings: summarizeFindings(allFindings),
    },
    extensions: extensionReports,
  };

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatTextReport(report));
  }

  if (errorCount > 0) {
    process.exit(2);
  }
  if (options.failOnNever && neverFindingCount > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(2);
});
