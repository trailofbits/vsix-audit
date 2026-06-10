import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
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
  cachedYaraExecutable = undefined;
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

type YaraFlavor = "yara-x" | "classic";

interface YaraExecutable {
  command: string;
  flavor: YaraFlavor;
}

const YARA_EXECUTABLE_CANDIDATES: YaraExecutable[] = [
  { command: "yr", flavor: "yara-x" },
  { command: "yara64", flavor: "classic" },
  { command: "yara", flavor: "classic" },
];

let cachedYaraExecutable: YaraExecutable | undefined;

function getConfiguredYaraExecutable(): YaraExecutable | undefined {
  const configured = process.env["VSIX_AUDIT_YARA_BIN"]?.trim();
  if (!configured) {
    return undefined;
  }

  const normalized = configured.toLowerCase();
  const flavor: YaraFlavor = normalized.includes("yr") && !normalized.includes("yara")
    ? "yara-x"
    : "classic";
  return { command: configured, flavor };
}

async function findYaraExecutable(): Promise<YaraExecutable | undefined> {
  if (cachedYaraExecutable) {
    return cachedYaraExecutable;
  }

  const candidates = [getConfiguredYaraExecutable(), ...YARA_EXECUTABLE_CANDIDATES].filter(
    (candidate, index, all): candidate is YaraExecutable => {
      if (!candidate) {
        return false;
      }
      return all.findIndex((other) => other?.command === candidate.command) === index;
    },
  );

  for (const candidate of candidates) {
    try {
      const { stdout, stderr } = await execFileAsync(candidate.command, ["--version"]);
      if (`${stdout}${stderr}`.trim().length > 0) {
        cachedYaraExecutable = candidate;
        return candidate;
      }
    } catch {
      // Try the next candidate.
    }
  }

  return undefined;
}

function getYaraInstallSuggestion(): string {
  return "Install YARA-X (`yr`) or classic YARA (`yara64`/`yara`), or set VSIX_AUDIT_YARA_BIN.";
}

function getYaraScanArgs(
  executable: YaraExecutable,
  rulesDir: string,
  ruleFiles: string[],
  targetDir: string,
): string[] {
  if (executable.flavor === "yara-x") {
    return ["scan", "-r", rulesDir, targetDir];
  }

  return ["-r", ...ruleFiles.map((ruleFile) => join(rulesDir, ruleFile)), targetDir];
}

function toRelativeMatchPath(tempDir: string, matchPath: string): string {
  const relativePath = relative(tempDir, matchPath);
  if (!relativePath || relativePath.startsWith("..")) {
    return matchPath.replace(/\\/g, "/");
  }
  return relativePath.replace(/\\/g, "/");
}

/**
 * Check if a supported YARA executable is installed and available
 */
export async function isYaraAvailable(): Promise<boolean> {
  return (await findYaraExecutable()) !== undefined;
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
  const lines = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

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

const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const DEPENDENCY_PATH_SUPPRESSED_RULES = new Set([
  "LOADER_JS_Download_Write_Execute_Jan25",
  "STEALER_JS_Credential_File_Exfil_Jan25",
  "SUSP_JS_Eval_Base64_Jan25",
  "SUSP_JS_Eval_Charcode_Jan25",
  "SUSP_JS_Obfuscation_Eval_Jan25",
  "SUSP_JS_Function_Constructor_Jan25",
  "SUSP_JS_Child_Process_Variable_Jan25",
  "SUSP_JS_Decimal_Byte_Array_Jan25",
  "SUSP_JS_Hex_Escape_Chain_Jan25",
  "SUSP_JS_String_Array_Rotation_Jan25",
]);
const GENERATED_PATH_SUPPRESSED_RULES = new Set([
  "LOADER_JS_Download_Write_Execute_Jan25",
  "RAT_JS_GlassWorm_Remote_Exec_Jan25",
  "STEALER_JS_Credential_File_Exfil_Jan25",
  "SUSP_JS_Eval_Base64_Jan25",
  "SUSP_JS_Eval_Charcode_Jan25",
  "SUSP_JS_Obfuscation_Eval_Jan25",
  "SUSP_JS_Function_Constructor_Jan25",
  "SUSP_JS_Child_Process_Variable_Jan25",
  "SUSP_JS_Decimal_Byte_Array_Jan25",
  "SUSP_JS_Hex_Escape_Chain_Jan25",
  "SUSP_JS_String_Array_Rotation_Jan25",
]);
const LOW_SIGNAL_CONTEXT_SUPPRESSED_RULES = new Set(["SUSP_JS_WebAssembly_Remote_Jan25"]);

function isDocumentationOrDeclarationPath(normalizedPath: string): boolean {
  const lowerPath = normalizedPath.toLowerCase();
  return (
    lowerPath.endsWith(".md") ||
    lowerPath.endsWith(".markdown") ||
    lowerPath.endsWith(".d.ts") ||
    lowerPath.includes("/readme.")
  );
}

function shouldSuppressYaraMatch(rule: string, relativePath: string): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  const isDependencyPath =
    normalizedPath.startsWith("node_modules/") || normalizedPath.includes("/node_modules/");
  const isGeneratedPath =
    normalizedPath.startsWith("dist/") ||
    normalizedPath.startsWith("out/") ||
    normalizedPath.startsWith("build/") ||
    normalizedPath.startsWith("lib/");

  if (
    (isDependencyPath && DEPENDENCY_PATH_SUPPRESSED_RULES.has(rule)) ||
    (isGeneratedPath && GENERATED_PATH_SUPPRESSED_RULES.has(rule))
  ) {
    return true;
  }

  if (
    LOW_SIGNAL_CONTEXT_SUPPRESSED_RULES.has(rule) &&
    (isDependencyPath || isGeneratedPath || isDocumentationOrDeclarationPath(normalizedPath))
  ) {
    return true;
  }

  return false;
}

async function buildYaraFinding(
  match: YaraMatch,
  ruleSourceMap: Map<string, string>,
  targetRulesDir: string,
  tempDir: string,
): Promise<Finding> {
  const ruleFile = ruleSourceMap.get(match.rule) ?? "unknown";
  const rulePath = join(targetRulesDir, ruleFile);
  const meta = await getRuleMeta(rulePath, match.rule);
  const relativePath = toRelativeMatchPath(tempDir, match.file);
  const fileExt = relativePath.slice(relativePath.lastIndexOf(".")).toLowerCase();
  const severity = VALID_SEVERITIES.has(meta.severity ?? "")
    ? (meta.severity as Finding["severity"])
    : "medium";

  return {
    id: `YARA_${match.rule}`,
    title: `YARA rule match: ${match.rule}`,
    description:
      `YARA rule "${match.rule}" from ${ruleFile} ` +
      "matched this file. This indicates the file " +
      "contains patterns associated with known " +
      "malware or suspicious behavior.",
    severity,
    category: "yara",
    location: { file: relativePath },
    metadata: {
      rule: match.rule,
      ruleFile,
      fileType: fileExt,
    },
  };
}

/**
 * Run YARA rules against extension contents
 */
export async function checkYara(contents: VsixContents, rulesDir?: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const targetRulesDir = rulesDir ?? (await getDefaultYaraRulesDir());
  const executable = await findYaraExecutable();

  // Check if YARA is available
  if (!executable) {
    findings.push({
      id: "YARA_NOT_INSTALLED",
      title: "YARA scanner not available",
      description:
        "No supported YARA executable was found. Install YARA-X (`yr`) or classic YARA (`yara64`/`yara`) to enable signature-based malware detection.",
      severity: "low",
      category: "yara",
      metadata: {
        suggestion: getYaraInstallSuggestion(),
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

    const scanArgs = getYaraScanArgs(executable, targetRulesDir, rules, tempDir);

    // Single YARA invocation scanning all rules at once.
    try {
      const { stdout, stderr } = await execFileAsync(executable.command, scanArgs, {
        maxBuffer: 10 * 1024 * 1024,
      });

      if (stderr && !stderr.includes("warning")) {
        // Log but don't fail - partial results may still be useful
      }

      const matches = parseYaraOutput(stdout);

      for (const match of matches) {
        const relativePath = toRelativeMatchPath(tempDir, match.file);
        if (shouldSuppressYaraMatch(match.rule, relativePath)) {
          continue;
        }
        findings.push(await buildYaraFinding(match, ruleSourceMap, targetRulesDir, tempDir));
      }
    } catch (error) {
      const execError = error as { stdout?: string; stderr?: string; code?: number };
      const partialMatches = parseYaraOutput(execError.stdout ?? "");
      for (const match of partialMatches) {
        const relativePath = toRelativeMatchPath(tempDir, match.file);
        if (shouldSuppressYaraMatch(match.rule, relativePath)) {
          continue;
        }
        findings.push(await buildYaraFinding(match, ruleSourceMap, targetRulesDir, tempDir));
      }

      const shouldSuppressScanError =
        executable.flavor === "classic" &&
        partialMatches.length > 0 &&
        (execError.stderr ?? "").trim().length === 0;
      if (shouldSuppressScanError) {
        return findings;
      }

      findings.push({
        id: "YARA_SCAN_ERROR",
        title: "YARA scan encountered errors",
        description:
          `The ${executable.command} YARA executable reported errors during scan. ` +
          "Some rules may not have been applied, " +
          "reducing detection coverage.",
        severity: "low",
        category: "yara",
        metadata: {
          executable: executable.command,
          flavor: executable.flavor,
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
