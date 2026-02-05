import { execFile } from "node:child_process";
import { access, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

/**
 * Get the default YARA rules directory (cached)
 */
export async function getDefaultYaraRulesDir(): Promise<string> {
  if (!cachedYaraRulesDir) {
    cachedYaraRulesDir = await findYaraRulesDir();
  }
  return cachedYaraRulesDir;
}

// For backwards compatibility - returns a path that may not exist until findYaraRulesDir is called
export const DEFAULT_YARA_RULES_DIR = join(
  __dirname,
  "..",
  "..",
  "..",
  "zoo",
  "signatures",
  "yara",
);

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
 * Get YARA-X version string
 */
export async function getYaraVersion(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("yr", ["--version"]);
    return stdout.trim();
  } catch {
    return null;
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
  } catch {
    // If we can't read the file, return empty map
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

  // Create a temporary directory for scanning
  const tempDir = join(tmpdir(), `vsix-audit-${Date.now()}`);

  try {
    // Write extension files to temp directory for YARA to scan
    const { mkdir } = await import("node:fs/promises");
    await mkdir(tempDir, { recursive: true });

    for (const [filename, buffer] of contents.files) {
      // Skip binary files that are too large
      if (buffer.length > 10 * 1024 * 1024) continue; // Skip files > 10MB

      // Skip binary files that cause false positives
      if (shouldSkipForYara(filename)) continue;

      const filePath = join(tempDir, filename);
      await mkdir(dirname(filePath), { recursive: true });
      await writeFile(filePath, buffer);
    }

    // Run YARA against the temp directory with all rules
    for (const ruleFile of rules) {
      const rulePath = join(targetRulesDir, ruleFile);

      try {
        // Run YARA-X with recursive scanning
        // Using execFile instead of exec to prevent command injection
        const { stdout, stderr } = await execFileAsync(
          "yr",
          ["scan", "-r", rulePath, tempDir],
          { maxBuffer: 10 * 1024 * 1024 }, // 10MB buffer for large outputs
        );

        if (stderr && !stderr.includes("warning")) {
          // YARA-X errors (not warnings) indicate rule issues
          continue;
        }

        const matches = parseYaraOutput(stdout);

        for (const match of matches) {
          // Get rule metadata
          const meta = await getRuleMeta(rulePath, match.rule);

          // Convert temp path back to relative path
          const relativePath = match.file.replace(tempDir + "/", "");

          // Get file extension for metadata
          const fileExt = relativePath.slice(relativePath.lastIndexOf(".")).toLowerCase();

          findings.push({
            id: `YARA_${match.rule}`,
            title: `YARA rule match: ${match.rule}`,
            description: `YARA rule "${match.rule}" from ${ruleFile} matched this file. This indicates the file contains patterns associated with known malware or suspicious behavior.`,
            severity: (meta.severity as "low" | "medium" | "high" | "critical") ?? "medium",
            category: "yara",
            location: {
              file: relativePath,
            },
            metadata: {
              rule: match.rule,
              ruleFile,
              fileType: fileExt,
            },
          });
        }
      } catch (error) {
        // YARA returns exit code 1 when no matches, which throws in exec
        // Only log actual errors
        if (error instanceof Error && !error.message.includes("exit code 1")) {
          // Silently ignore scan errors for individual rules
        }
      }
    }
  } finally {
    // Clean up temp directory
    try {
      await rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }

  return findings;
}
