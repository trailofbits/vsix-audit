import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { Finding, VsixContents } from "../types.js";

/**
 * Binary file extensions that should be skipped for YARA scanning.
 * These cause false positives because YARA pattern matching on binary
 * content often matches arbitrary byte sequences.
 */
const BINARY_EXTENSIONS = new Set([
  // Java
  ".jar",
  ".class",
  ".war",
  ".ear",
  // Compiled
  ".wasm",
  ".pyc",
  ".pyo",
  // Images
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".bmp",
  ".ico",
  ".webp",
  ".svg",
  ".tiff",
  ".tif",
  // Fonts
  ".ttf",
  ".otf",
  ".woff",
  ".woff2",
  ".eot",
  // Audio/Video
  ".mp3",
  ".mp4",
  ".wav",
  ".ogg",
  ".webm",
  ".avi",
  // Archives
  ".zip",
  ".tar",
  ".gz",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  // Documents
  ".pdf",
  // Native binaries (scanned separately by checkNativeFiles)
  ".node",
  ".dll",
  ".dylib",
  ".so",
  ".exe",
  // Other binary
  ".bin",
  ".dat",
]);

/**
 * Check if a file should be skipped for YARA scanning
 */
function shouldSkipForYara(filename: string): boolean {
  const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

const execFileAsync = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Find the YARA rules directory, checking multiple locations.
 * Priority:
 * 1. VSIX_AUDIT_ZOO_PATH environment variable + /signatures/yara
 * 2. Development: ../../../zoo/signatures/yara relative to module
 * 3. Installed: ../../zoo/signatures/yara relative to dist
 */
async function findYaraRulesDir(): Promise<string> {
  // Check environment variable first
  const envPath = process.env["VSIX_AUDIT_ZOO_PATH"];
  if (envPath) {
    return join(envPath, "signatures", "yara");
  }

  // Development path: src/scanner/checks -> zoo/signatures/yara
  const devPath = join(__dirname, "..", "..", "..", "zoo", "signatures", "yara");
  try {
    await access(devPath);
    return devPath;
  } catch {
    // Not found, try installed path
  }

  // Installed path: dist/scanner/checks -> zoo/signatures/yara
  const installedPath = join(__dirname, "..", "..", "zoo", "signatures", "yara");
  try {
    await access(installedPath);
    return installedPath;
  } catch {
    // Fall back to dev path (will error with helpful message later)
    return devPath;
  }
}

// Cached result of findYaraRulesDir
let cachedYaraRulesDir: string | undefined;

/** Reset module caches (for testing) */
export function resetYaraCaches(): void {
  cachedYaraRulesDir = undefined;
  ruleMetaCache.clear();
}

/**
 * Get the default YARA rules directory (cached)
 */
export async function getDefaultYaraRulesDir(): Promise<string> {
  if (!cachedYaraRulesDir) {
    cachedYaraRulesDir = await findYaraRulesDir();
  }
  return cachedYaraRulesDir;
}

interface YaraMatch {
  rule: string;
  file: string;
  strings?: string[];
  meta?: Record<string, string>;
}

/**
 * Check if YARA-X is installed and available
 */
export async function isYaraAvailable(): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("yr", ["--version"]);
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * List all YARA rule files in a directory
 */
export async function listYaraRules(rulesDir: string): Promise<string[]> {
  try {
    const entries = await readdir(rulesDir);
    return entries.filter((f) => f.endsWith(".yar") || f.endsWith(".yara"));
  } catch {
    return [];
  }
}

/**
 * Parse YARA output into structured matches
 */
function parseYaraOutput(output: string): YaraMatch[] {
  const matches: YaraMatch[] = [];
  const lines = output.trim().split("\n").filter(Boolean);

  for (const line of lines) {
    // YARA output format: rule_name file_path
    // With -s flag: rule_name file_path\n0xoffset:$string_name: string_content
    const match = line.match(/^(\S+)\s+(.+)$/);
    if (match) {
      const [, rule, file] = match;
      if (rule && file) {
        matches.push({ rule, file });
      }
    }
  }

  return matches;
}

/**
 * Cache for parsed YARA rule metadata to avoid re-reading files
 */
const ruleMetaCache = new Map<string, Map<string, { severity?: string; description?: string }>>();

/**
 * Accumulated errors from parseRuleFile, drained by checkYara.
 */
const ruleFileErrors: { ruleFile: string; error: string }[] = [];

/**
 * Parse YARA rule file and extract metadata for all rules
 */
async function parseRuleFile(
  ruleFile: string,
): Promise<Map<string, { severity?: string; description?: string }>> {
  if (ruleMetaCache.has(ruleFile)) {
    return ruleMetaCache.get(ruleFile)!;
  }

  const { readFile } = await import("node:fs/promises");
  const ruleMap = new Map<string, { severity?: string; description?: string }>();

  try {
    const content = await readFile(ruleFile, "utf8");

    // Match rule blocks: rule NAME { meta: ... }
    const rulePattern = /rule\s+(\w+)\s*\{[^}]*meta\s*:\s*([^}]+?)(?:strings|condition)\s*:/gs;

    for (const match of content.matchAll(rulePattern)) {
      const ruleName = match[1];
      const metaBlock = match[2];

      if (!ruleName || !metaBlock) continue;

      const meta: { severity?: string; description?: string } = {};

      // Extract severity from meta block
      const severityMatch = metaBlock.match(/severity\s*=\s*["'](\w+)["']/);
      if (severityMatch?.[1]) {
        meta.severity = severityMatch[1];
      }

      // Extract description from meta block
      const descMatch = metaBlock.match(/description\s*=\s*["']([^"']+)["']/);
      if (descMatch?.[1]) {
        meta.description = descMatch[1];
      }

      ruleMap.set(ruleName, meta);
    }
  } catch (error) {
    ruleFileErrors.push({
      ruleFile,
      error: error instanceof Error ? error.message : String(error),
    });
  }

  ruleMetaCache.set(ruleFile, ruleMap);
  return ruleMap;
}

/**
 * Extract metadata from YARA rule file for a specific rule
 */
async function getRuleMeta(
  ruleFile: string,
  ruleName: string,
): Promise<{ severity?: string; description?: string }> {
  const ruleMap = await parseRuleFile(ruleFile);
  const meta = ruleMap.get(ruleName);

  if (meta?.severity) {
    return meta;
  }

  // Fallback: derive severity from rule name patterns
  const result: { severity?: string; description?: string } = {};
  if (meta?.description) {
    result.description = meta.description;
  }

  const lowerName = ruleName.toLowerCase();
  if (lowerName.includes("critical") || lowerName.startsWith("mal_")) {
    result.severity = "critical";
  } else if (
    lowerName.includes("stealth") ||
    lowerName.startsWith("stealer_") ||
    lowerName.startsWith("rat_") ||
    lowerName.startsWith("c2_")
  ) {
    result.severity = "high";
  } else if (lowerName.startsWith("susp_") || lowerName.startsWith("loader_")) {
    result.severity = "medium";
  } else {
    result.severity = "medium"; // Default
  }

  return result;
}

/**
 * Run YARA rules against extension contents
 */
export async function checkYara(contents: VsixContents, rulesDir?: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const targetRulesDir = rulesDir ?? (await getDefaultYaraRulesDir());

  // Check if YARA is available
  const available = await isYaraAvailable();
  if (!available) {
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
    return findings;
  }

  // Check if rules directory exists and has rules
  const rules = await listYaraRules(targetRulesDir);
  if (rules.length === 0) {
    return findings;
  }

  // Create a temporary directory for scanning (mkdtemp is atomic + unpredictable)
  const tempDir = await mkdtemp(join(tmpdir(), "vsix-audit-"));

  try {
    // Collect files to write, filtering out binary/large/traversal
    const filesToWrite: Array<{ path: string; buffer: Buffer }> = [];
    const dirsNeeded = new Set<string>();

    for (const [filename, buffer] of contents.files) {
      if (buffer.length > 10 * 1024 * 1024) continue;
      if (shouldSkipForYara(filename)) continue;
      const filePath = join(tempDir, filename);
      if (!resolve(filePath).startsWith(resolve(tempDir))) continue;
      dirsNeeded.add(dirname(filePath));
      filesToWrite.push({ path: filePath, buffer });
    }

    // Create all directories in parallel
    await Promise.all([...dirsNeeded].map((d) => mkdir(d, { recursive: true })));

    // Write all files in parallel
    await Promise.all(filesToWrite.map((f) => writeFile(f.path, f.buffer)));

    // Pre-parse rule files to build ruleName -> ruleFile map
    const ruleSourceMap = new Map<string, string>();
    for (const ruleFile of rules) {
      const rulePath = join(targetRulesDir, ruleFile);
      const ruleMap = await parseRuleFile(rulePath);
      for (const ruleName of ruleMap.keys()) {
        ruleSourceMap.set(ruleName, ruleFile);
      }
    }

    // Single YARA-X invocation scanning all rules at once
    try {
      const { stdout, stderr } = await execFileAsync(
        "yr",
        ["scan", "-r", targetRulesDir, tempDir],
        { maxBuffer: 10 * 1024 * 1024 },
      );

      if (stderr && !stderr.includes("warning")) {
        // Log but don't fail - partial results may still be useful
      }

      const matches = parseYaraOutput(stdout);

      for (const match of matches) {
        const ruleFile = ruleSourceMap.get(match.rule) ?? "unknown";
        const rulePath = join(targetRulesDir, ruleFile);
        const meta = await getRuleMeta(rulePath, match.rule);

        const relativePath = match.file.replace(tempDir + "/", "");
        const fileExt = relativePath.slice(relativePath.lastIndexOf(".")).toLowerCase();

        findings.push({
          id: `YARA_${match.rule}`,
          title: `YARA rule match: ${match.rule}`,
          description:
            `YARA rule "${match.rule}" from ${ruleFile} ` +
            "matched this file. This indicates the file " +
            "contains patterns associated with known " +
            "malware or suspicious behavior.",
          severity: (meta.severity as "low" | "medium" | "high" | "critical") ?? "medium",
          category: "yara",
          location: { file: relativePath },
          metadata: {
            rule: match.rule,
            ruleFile,
            fileType: fileExt,
          },
        });
      }
    } catch (error) {
      // YARA-X (yr) exit codes: 0 = success (matches or no matches), 1+ = error.
      // execFileAsync throws on any non-zero exit code. Unlike legacy YARA,
      // YARA-X does NOT use exit code 1 for "no matches" — it always means
      // an actual error (bad rules, missing files, etc.).
      // Recover any partial matches from stdout before reporting the error.
      const execError = error as { stdout?: string; stderr?: string; code?: number };
      if (execError.stdout) {
        const partialMatches = parseYaraOutput(execError.stdout);
        for (const match of partialMatches) {
          const ruleFile = ruleSourceMap.get(match.rule) ?? "unknown";
          const rulePath = join(targetRulesDir, ruleFile);
          const meta = await getRuleMeta(rulePath, match.rule);
          const relativePath = match.file.replace(tempDir + "/", "");
          const fileExt = relativePath.slice(relativePath.lastIndexOf(".")).toLowerCase();

          findings.push({
            id: `YARA_${match.rule}`,
            title: `YARA rule match: ${match.rule}`,
            description:
              `YARA rule "${match.rule}" from ${ruleFile} ` +
              "matched this file. This indicates the file " +
              "contains patterns associated with known " +
              "malware or suspicious behavior.",
            severity: (meta.severity as "low" | "medium" | "high" | "critical") ?? "medium",
            category: "yara",
            location: { file: relativePath },
            metadata: {
              rule: match.rule,
              ruleFile,
              fileType: fileExt,
            },
          });
        }
      }

      findings.push({
        id: "YARA_SCAN_ERROR",
        title: "YARA scan encountered errors",
        description:
          "YARA-X reported errors during scan. " +
          "Some rules may not have been applied, " +
          "reducing detection coverage.",
        severity: "low",
        category: "yara",
        metadata: {
          error: error instanceof Error ? error.message : String(error),
          stderr: execError.stderr ?? "",
          exitCode: execError.code,
        },
      });
    }
  } finally {
    // Clean up temp directory
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch (error) {
      findings.push({
        id: "YARA_CLEANUP_FAILURE",
        title: "Failed to clean up temp scan files",
        description:
          "Temporary files from YARA scanning " +
          "could not be removed. Extension data " +
          "may remain in the temp directory.",
        severity: "low",
        category: "yara",
        metadata: {
          tempDir,
          error: error instanceof Error ? error.message : String(error),
        },
      });
    }
  }

  // Drain any rule-file parse errors into findings
  while (ruleFileErrors.length > 0) {
    const err = ruleFileErrors.pop()!;
    findings.push({
      id: "YARA_RULE_PARSE_ERROR",
      title: "Failed to parse YARA rule file metadata",
      description:
        "A YARA rule file could not be read or " +
        "parsed for metadata. Rule severity may " +
        "default to medium, degrading triage accuracy.",
      severity: "low",
      category: "yara",
      location: { file: err.ruleFile },
      metadata: {
        ruleFile: err.ruleFile,
        error: err.error,
      },
    });
  }

  return findings;
}
