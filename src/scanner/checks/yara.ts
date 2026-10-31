import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { getZooRoot } from "#internal/scanner/loaders/zoo.js";
import type {
  Capability,
  CheckResult,
  Finding,
  Severity,
  VsixContents,
} from "#internal/scanner/types.js";
import { CAPABILITY_NAMES, SEVERITIES } from "#internal/scanner/types.js";

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
    const { stdout } = await execFileAsync("yr", ["--version"]);
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

function toFinding(rule: unknown, file: string, rulesDir: string): Finding {
  if (
    !isRecord(rule) ||
    typeof rule["identifier"] !== "string" ||
    typeof rule["namespace"] !== "string"
  ) {
    throw new Error("YARA-X match is missing its rule identifier or source namespace.");
  }
  const metadata = ruleMetadata(rule["meta"]);
  const severity = metadata.get("severity");
  if (typeof severity !== "string" || !SEVERITIES.includes(severity as Severity)) {
    throw new Error(`YARA rule ${rule["identifier"]} must declare a valid severity.`);
  }
  const ruleFile = relative(rulesDir, rule["namespace"]).split(sep).join("/");
  const description = metadata.get("description");
  return {
    id: `YARA_${rule["identifier"]}`,
    title: `YARA rule match: ${rule["identifier"]}`,
    description:
      typeof description === "string"
        ? description
        : `YARA rule "${rule["identifier"]}" from ${ruleFile} matched this file. ` +
          "Review the matched behavior.",
    severity: severity as Severity,
    category: "yara",
    location: { file },
    capabilities: ruleCapabilities(metadata.get("capabilities")),
    metadata: {
      rule: rule["identifier"],
      ruleFile,
      ...(metadata.has("evidence") ? { evidence: metadata.get("evidence") } : {}),
      fileType: file.slice(file.lastIndexOf(".")).toLowerCase(),
    },
  };
}

function parseRecord(line: string): { path: string; rules: unknown[] } {
  const record: unknown = JSON.parse(line);
  if (!isRecord(record) || typeof record["path"] !== "string" || !Array.isArray(record["rules"])) {
    throw new Error("YARA-X output must contain a path and rules array.");
  }
  return { path: record["path"], rules: record["rules"] };
}

function readMatches(output: string, tempDir: string, rulesDir: string, result: CheckResult): void {
  for (const line of output.split("\n").filter(Boolean)) {
    try {
      const record = parseRecord(line);
      const file = relative(tempDir, record.path);
      if (file === "" || isAbsolute(file) || file === ".." || file.startsWith(`..${sep}`)) {
        throw new Error("YARA-X reported a path outside its scan directory.");
      }
      for (const rule of record.rules)
        result.findings.push(toFinding(rule, file.split(sep).join("/"), rulesDir));
    } catch (error) {
      addFailure(
        result,
        "YARA_OUTPUT_ERROR",
        `Cannot read YARA-X matches: ${String(error)}. ` +
          "Check the rule metadata and YARA-X installation, then retry.",
      );
    }
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

function processOutput(error: unknown, field: "stdout" | "stderr"): string {
  if (!(error instanceof Error) || !(field in error)) return "";
  const value = (error as unknown as Record<string, unknown>)[field];
  return typeof value === "string" ? value : "";
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
    try {
      const { stdout, stderr } = await execFileAsync(
        "yr",
        [
          "scan",
          "-r",
          "--output-format=ndjson",
          "--print-meta",
          "--print-namespace",
          "--path-as-namespace",
          targetRulesDir,
          directory,
        ],
        { maxBuffer: 10 * 1024 * 1024 },
      );
      readMatches(stdout, directory, targetRulesDir, result);
      if (stderr.trim() !== "") {
        addFailure(
          result,
          "YARA_DIAGNOSTIC",
          `YARA-X diagnostics: ${stderr.trim()}. Review the rules and retry.`,
        );
      }
    } catch (error) {
      readMatches(processOutput(error, "stdout"), directory, targetRulesDir, result);
      addFailure(
        result,
        "YARA_SCAN_ERROR",
        `YARA-X scan failed: ${String(error)}. ` +
          `${processOutput(error, "stderr")} Check the rules and retry.`,
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
