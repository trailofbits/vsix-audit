import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { getZooRoot } from "#internal/scanner/loaders/zoo.js";
import { isCompiledFile } from "#internal/scanner/native.js";
import { runYara } from "#internal/scanner/checks/yara-process.js";
import type {
  Capability,
  CheckResult,
  Finding,
  Severity,
  VsixContents,
  YaraStringMatch,
} from "#internal/scanner/types.js";
import { CAPABILITY_NAMES, SEVERITIES } from "#internal/scanner/types.js";
import { evidenceLocation, readStringMatches } from "#internal/scanner/checks/yara-evidence.js";

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
  // Native binaries are outside these script-oriented rules
  ".node",
  ".dll",
  ".dylib",
  ".so",
  ".exe",
  // Other binary
  ".bin",
  ".dat",
]);

const execFileAsync = promisify(execFile);
const MAX_YARA_FILE_SIZE = 10 * 1024 * 1024;

/** Check whether the YARA-X executable can run. */
export async function isYaraAvailable(): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync("yr", ["--version"], {
      timeout: 5_000,
      killSignal: "SIGKILL",
    });
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/** List rule files, preserving errors instead of silently disabling scanning. */
export async function listYaraRules(rulesDir: string): Promise<string[]> {
  const entries = await readdir(rulesDir, { recursive: true });
  return entries.filter((name) => /\.yara?$/.test(name));
}

function addFailure(result: CheckResult, id: string, message: string): void {
  result.warnings.push(message);
  result.findings.push({
    id,
    title: "YARA coverage incomplete",
    description: message,
    severity: "low",
    category: "yara",
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ruleMetadata(value: unknown): Map<string, unknown> {
  if (!Array.isArray(value)) throw new Error("YARA-X rule metadata must be an array.");
  const metadata = new Map<string, unknown>();
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string") {
      throw new Error("YARA-X rule metadata must contain name/value pairs.");
    }
    metadata.set(entry[0], entry[1]);
  }
  return metadata;
}

function ruleCapabilities(value: unknown): Capability[] {
  if (value === undefined) return [];
  if (typeof value !== "string") throw new Error("YARA rule capabilities must be a string.");
  const names = value.split(",").map((name) => name.trim());
  if (!names.every((name) => CAPABILITY_NAMES.includes(name as Capability))) {
    throw new Error("YARA rule capabilities contain an unknown capability.");
  }
  return names as Capability[];
}

function readEvidence(
  rule: Record<string, unknown>,
  buffer: Buffer,
  result: CheckResult,
): YaraStringMatch[] {
  try {
    const maximum = rule["evidenceMaxOffset"];
    if (typeof maximum === "number" && maximum > buffer.length) {
      throw new Error("YARA-X string offset is outside the scanned file.");
    }
    if (typeof rule["evidenceError"] === "string") throw new Error(rule["evidenceError"]);
    return readStringMatches(rule["strings"], buffer);
  } catch (error) {
    addFailure(
      result,
      "YARA_OUTPUT_ERROR",
      `Cannot read YARA-X string evidence: ${String(error)}. ` +
        "The rule match is retained. Check the YARA-X installation and retry.",
    );
    return [];
  }
}

function ruleSeverity(identifier: string, value: unknown): Severity {
  if (typeof value !== "string" || !SEVERITIES.includes(value as Severity)) {
    throw new Error(`YARA rule ${identifier} must declare a valid severity.`);
  }
  return value as Severity;
}

function toFinding(
  rule: unknown,
  file: string,
  rulesDir: string,
  buffer: Buffer,
  result: CheckResult,
): Finding {
  if (
    !isRecord(rule) ||
    typeof rule["identifier"] !== "string" ||
    typeof rule["namespace"] !== "string"
  ) {
    throw new Error("YARA-X match is missing its rule identifier or source namespace.");
  }
  const metadata = ruleMetadata(rule["meta"]);
  const severity = ruleSeverity(rule["identifier"], metadata.get("severity"));
  const ruleFile = relative(rulesDir, rule["namespace"]).split(sep).join("/");
  const description = metadata.get("description");
  const matches = readEvidence(rule, buffer, result);
  return {
    id: `YARA_${rule["identifier"]}`,
    title: `YARA rule match: ${rule["identifier"]}`,
    description:
      typeof description === "string"
        ? description
        : `YARA rule "${rule["identifier"]}" from ${ruleFile} matched this file. ` +
          "Review the matched behavior.",
    severity,
    category: "yara",
    location: evidenceLocation(file, matches, buffer),
    capabilities: ruleCapabilities(metadata.get("capabilities")),
    metadata: {
      rule: rule["identifier"],
      ruleFile,
      matches,
      totalMatches:
        typeof rule["totalMatches"] === "number" ? rule["totalMatches"] : matches.length,
      ...(metadata.has("evidence") ? { evidence: metadata.get("evidence") } : {}),
      fileType: file.slice(file.lastIndexOf(".")).toLowerCase(),
    },
  };
}

function parseRecord(record: unknown, tempDir: string): { file: string; rules: unknown[] } {
  if (!isRecord(record) || typeof record["path"] !== "string" || !Array.isArray(record["rules"])) {
    throw new Error("YARA-X output must contain a path and rules array.");
  }
  const file = relative(tempDir, record["path"]);
  if (file === "" || isAbsolute(file) || file === ".." || file.startsWith(`..${sep}`)) {
    throw new Error("YARA-X reported a path outside its scan directory.");
  }
  return { file: file.split(sep).join("/"), rules: record["rules"] };
}

function readRecord(
  value: unknown,
  tempDir: string,
  rulesDir: string,
  result: CheckResult,
  contents: VsixContents,
): void {
  try {
    const record = parseRecord(value, tempDir);
    const buffer = contents.files.get(record.file);
    if (buffer === undefined) throw new Error("YARA-X reported an unknown file.");
    for (const rule of record.rules) {
      try {
        result.findings.push(toFinding(rule, record.file, rulesDir, buffer, result));
      } catch (error) {
        addFailure(
          result,
          "YARA_OUTPUT_ERROR",
          `Cannot read YARA-X rule metadata: ${String(error)}. Check the rules and retry.`,
        );
      }
    }
  } catch (error) {
    addFailure(
      result,
      "YARA_OUTPUT_ERROR",
      `Cannot read YARA-X matches: ${String(error)}. ` +
        "Check the rule metadata and YARA-X installation, then retry.",
    );
  }
}

async function writeScanFiles(
  contents: VsixContents,
  directory: string,
  result: CheckResult,
): Promise<void> {
  const files: Array<{ path: string; buffer: Buffer }> = [];
  const directories = new Set<string>();
  for (const [filename, buffer] of contents.files) {
    if (isCompiledFile(filename, buffer)) {
      addFailure(
        result,
        "YARA_SKIPPED_BINARY",
        `YARA-X skipped ${JSON.stringify(filename)}: ` +
          "the bundled script rules do not analyze this compiled format. Inspect it with " +
          "tools for its executable format.",
      );
      continue;
    }
    const extension = filename.slice(filename.lastIndexOf(".")).toLowerCase();
    if (BINARY_EXTENSIONS.has(extension)) continue;
    const path = resolve(directory, filename);
    if (!path.startsWith(resolve(directory) + sep) || buffer.length > MAX_YARA_FILE_SIZE) {
      addFailure(
        result,
        "YARA_SKIPPED_FILE",
        `YARA-X skipped ${JSON.stringify(filename)}: ` +
          "unsafe path or file exceeds 10 MiB. Inspect the file manually.",
      );
      continue;
    }
    directories.add(dirname(path));
    files.push({ path, buffer });
  }
  await Promise.all([...directories].map((path) => mkdir(path, { recursive: true })));
  await Promise.all(files.map((file) => writeFile(file.path, file.buffer)));
}

async function removeScanDirectory(directory: string, result: CheckResult): Promise<void> {
  try {
    await rm(directory, { recursive: true, force: true });
  } catch (error) {
    addFailure(
      result,
      "YARA_CLEANUP_FAILURE",
      `Cannot remove YARA-X temporary directory ${directory}: ` +
        `${String(error)}. Remove the temporary files after fixing permissions.`,
    );
  }
}

/** Scan eligible files using YARA-X structured output, retaining partial matches and failures. */
export async function checkYara(contents: VsixContents, rulesDir?: string): Promise<CheckResult> {
  const result: CheckResult = { findings: [], warnings: [] };
  const targetRulesDir = rulesDir ?? join(getZooRoot(), "signatures", "yara");
  if (!(await isYaraAvailable())) {
    addFailure(
      result,
      "YARA_NOT_INSTALLED",
      "YARA-X is unavailable. Install 'yr' with " +
        "'brew install yara-x' or use the Docker image, then retry.",
    );
    return result;
  }
  let directory: string | undefined;
  try {
    if ((await listYaraRules(targetRulesDir)).length === 0) {
      throw new Error(
        `No YARA rules in ${targetRulesDir}. Restore the bundled rules or fix VSIX_AUDIT_ZOO_PATH.`,
      );
    }
    directory = await mkdtemp(join(tmpdir(), "vsix-audit-"));
    await writeScanFiles(contents, directory, result);
    const scanDirectory = directory;
    try {
      const stderr = await runYara(
        [
          "scan",
          "-r",
          "--output-format=ndjson",
          "--print-meta",
          "--print-strings=120",
          "--print-namespace",
          "--path-as-namespace",
          targetRulesDir,
          directory,
        ],
        (record) => {
          readRecord(record, scanDirectory, targetRulesDir, result, contents);
        },
        (error) => {
          addFailure(
            result,
            "YARA_OUTPUT_ERROR",
            `Cannot read YARA-X output: ${String(error)}. Check YARA-X and retry.`,
          );
        },
      );
      if (stderr.trim() !== "") {
        addFailure(
          result,
          "YARA_DIAGNOSTIC",
          `YARA-X diagnostics: ${stderr.trim()}. Review the rules and retry.`,
        );
      }
    } catch (error) {
      addFailure(
        result,
        "YARA_SCAN_ERROR",
        `YARA-X scan failed: ${String(error)}. ` + "Check the rules and retry.",
      );
    }
  } catch (error) {
    addFailure(
      result,
      "YARA_SCAN_ERROR",
      `Cannot prepare YARA-X scan: ${String(error)}. ` +
        "Check the rule directory and file permissions, then retry.",
    );
  } finally {
    if (directory !== undefined) {
      await removeScanDirectory(directory, result);
    }
  }
  return result;
}
