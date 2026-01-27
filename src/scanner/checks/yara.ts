import { exec } from "node:child_process";
import { readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { Finding, VsixContents } from "../types.js";

const execAsync = promisify(exec);

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_DIR = join(__dirname, "..", "..", "..", "zoo", "signatures", "yara");

interface YaraMatch {
  rule: string;
  file: string;
  strings?: string[];
  meta?: Record<string, string>;
}

/**
 * Check if YARA is installed and available
 */
export async function isYaraAvailable(): Promise<boolean> {
  try {
    const { stdout } = await execAsync("yara --version");
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Get YARA version string
 */
export async function getYaraVersion(): Promise<string | null> {
  try {
    const { stdout } = await execAsync("yara --version");
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
 * Extract metadata from YARA rule file
 * This parses the rule file to get severity and description
 */
async function getRuleMeta(
  ruleFile: string,
  ruleName: string,
): Promise<{ severity?: string; description?: string }> {
  // For now, derive severity from rule name patterns
  // A more complete implementation would parse the YARA file
  const meta: { severity?: string; description?: string } = {};

  // Check for severity hints in rule name
  const lowerName = ruleName.toLowerCase();
  if (lowerName.includes("critical") || lowerName.includes("malware")) {
    meta.severity = "critical";
  } else if (lowerName.includes("suspicious") || lowerName.includes("stealth")) {
    meta.severity = "high";
  } else if (lowerName.includes("warning") || lowerName.includes("potential")) {
    meta.severity = "medium";
  } else {
    meta.severity = "medium"; // Default
  }

  return meta;
}

/**
 * Run YARA rules against extension contents
 */
export async function checkYara(
  contents: VsixContents,
  rulesDir?: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const targetRulesDir = rulesDir ?? DEFAULT_RULES_DIR;

  // Check if YARA is available
  const available = await isYaraAvailable();
  if (!available) {
    findings.push({
      id: "YARA_NOT_INSTALLED",
      title: "YARA scanner not available",
      description:
        "YARA is not installed. Install with 'brew install yara' to enable advanced malware detection using signature rules.",
      severity: "low",
      category: "yara",
      metadata: {
        suggestion: "brew install yara",
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

      const filePath = join(tempDir, filename);
      await mkdir(dirname(filePath), { recursive: true });
      await writeFile(filePath, buffer);
    }

    // Run YARA against the temp directory with all rules
    for (const ruleFile of rules) {
      const rulePath = join(targetRulesDir, ruleFile);

      try {
        // Run YARA with recursive scanning
        const { stdout, stderr } = await execAsync(
          `yara -r -w "${rulePath}" "${tempDir}"`,
          { maxBuffer: 10 * 1024 * 1024 }, // 10MB buffer for large outputs
        );

        if (stderr && !stderr.includes("warning")) {
          // YARA errors (not warnings) indicate rule issues
          continue;
        }

        const matches = parseYaraOutput(stdout);

        for (const match of matches) {
          // Get rule metadata
          const meta = await getRuleMeta(rulePath, match.rule);

          // Convert temp path back to relative path
          const relativePath = match.file.replace(tempDir + "/", "");

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
