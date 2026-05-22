import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type {
  BlocklistEntry,
  Finding,
  MaliciousNpmVersionAdvisory,
  VsixContents,
  VsixManifest,
  ZooData,
} from "../types.js";
import { computeLineStarts, findLineNumberByIndex, getStringContent } from "../utils.js";

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

type PackageVersionEvidenceSource =
  | "package-lock"
  | "npm-shrinkwrap"
  | "package-lock-v1"
  | "npm-shrinkwrap-v1"
  | "bundled-node-module";

interface InstalledPackageEvidence {
  name: string;
  version: string;
  source: PackageVersionEvidenceSource;
  file: string;
}

// Known-good packages that are NOT typosquats despite edit distance
// These are legitimate packages that happen to be similar to popular packages
const KNOWN_GOOD_PACKAGES = new Set([
  // Testing and utilities
  "chai", // Testing library, not typosquat of chalk
  "async", // Async utilities, legitimate
  "debug", // Debug logging, legitimate

  // URL/file openers
  "open", // URL opener, not typosquat of openai
  "opener", // URL/file opener, not typosquat of openai

  // Linters (all legitimate, not typosquats of eslint)
  "tslint", // TypeScript linter (deprecated but legitimate)
  "xqlint", // XQuery linter

  // UUID and ID libraries
  "uuid4", // UUID v4 package, not typosquat of uuid
  "uuidv4", // Another UUID v4 package, not typosquat of uuid
  "ulid", // ULID library, different from UUID

  // Node.js core module shims
  "util", // Node.js util shim, not typosquat of uuid
  "os", // Node.js os shim, not typosquat of cors

  // Database drivers
  "mssql", // Microsoft SQL Server driver, not typosquat of mysql
  "mysql2", // MySQL2 driver (successor to mysql package)

  // React ecosystem
  "preact", // Lightweight React alternative, not typosquat

  // CLI utilities
  "colors", // CLI colors, not typosquat of cors

  // Build/config utilities
  "core", // Common name, not typosquat of cors
  "acorn", // JS parser, not typosquat of cors
  "cpr", // Recursive copy, not typosquat of cors
  "dotenv-expand", // dotenv companion, not typosquat
  "cross-spawn", // Spawn helper, not typosquat of cross-env
  "defu", // Deep defaults utility (unjs), not typosquat of debug
  "jsonc", // JSON with Comments parser, not typosquat of async
]);

// Popular packages and their common typosquats
const POPULAR_PACKAGES = new Map<string, string[]>([
  ["lodash", ["lodahs", "lodashs", "loadsh", "lodaash", "lo-dash", "lodassh"]],
  ["express", ["expres", "expresss", "exprees", "xpress"]],
  ["react", ["reect", "raect", "reactt", "reakt"]],
  ["axios", ["axois", "axio", "axioss", "axiosjs"]],
  ["moment", ["momment", "momnent", "momentjs"]],
  ["webpack", ["webpak", "webpackk", "web-pack"]],
  ["babel", ["babell", "bable", "babeel"]],
  ["eslint", ["esslint", "eslnt", "eslintjs"]],
  ["typescript", ["typscript", "tyepscript", "typescipt"]],
  ["mongoose", ["mongose", "mongoos", "mongoosee"]],
  ["jquery", ["jquerry", "jqeury", "jqueryjs", "jquery.js"]],
  ["chalk", ["challk", "chaulk", "chak"]],
  ["commander", ["comandar", "comander", "commanderjs"]],
  ["request", ["reqest", "requets", "requestjs"]],
  ["underscore", ["undrscore", "undescore", "underscorejs"]],
  ["async", ["asnyc", "asyncjs", "asynic"]],
  ["debug", ["debuf", "debgu", "debugjs"]],
  ["uuid", ["uuuid", "uuidjs", "uiid"]],
  ["dotenv", ["dtoenv", "dotenvjs", "dot-env"]],
  ["cors", ["corss", "corsjs", "cros"]],
  ["cross-env", ["crossenv", "cross-env.js", "cros-env"]],
  ["mysql", ["mysqljs", "my-sql", "mysqll"]],
  ["sqlite3", ["sqliter", "sqlite.js", "sqllite3"]],
  ["openai", ["openai-api", "open-ai", "openaijs"]],
  ["anthropic", ["anthropic-api", "anthopic", "antropic"]],
  ["langchain", ["langchain-core", "lang-chain", "langchainjs"]],
]);

// Dangerous npm lifecycle scripts
const DANGEROUS_SCRIPTS = [
  "preinstall",
  "postinstall",
  "preuninstall",
  "postuninstall",
  "prepublish",
  "postpublish",
];

// Patterns that indicate malicious script content
const MALICIOUS_SCRIPT_PATTERNS = [
  { pattern: /curl\s+.*\|\s*(ba)?sh/i, desc: "Downloads and executes remote script" },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i, desc: "Downloads and executes remote script" },
  { pattern: /eval\s*\(.*\$\(/i, desc: "Eval with command substitution" },
  { pattern: /node\s+-e\s+.*atob/i, desc: "Node.js eval with base64 decode" },
  { pattern: /powershell.*-enc/i, desc: "Encoded PowerShell command" },
  { pattern: /\bexec\s*\(.*http/i, desc: "Executes remote content" },
  { pattern: /\.ssh\/id_/i, desc: "SSH key access" },
  { pattern: /discord\.com\/api\/webhooks/i, desc: "Discord webhook (data exfiltration)" },
  { pattern: /crypto.*wallet/i, desc: "Cryptocurrency wallet access" },
  { pattern: /APPDATA.*Chrome/i, desc: "Chrome browser data access" },
  { pattern: /\.credentials/i, desc: "Credential file access" },
  { pattern: /keychain|keyring/i, desc: "System keychain access" },
];

const TASK_EXECUTION_PATTERN = /\b[\w$.]*executeTask\s*\(/;
const TASK_CONSTRUCTION_PATTERN = /\bnew\s+[\w$.]*Task\s*\(/;
const SHELL_EXECUTION_PATTERN = /\b[\w$.]*ShellExecution\s*\(/;
const PROCESS_LAUNCH_PATTERN =
  /\b(?:child_process|execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)\b/;
const HIDDEN_TASK_PATTERN =
  /presentationOptions\.(?:focus|echo)\s*=\s*(?:false|!1)|presentationOptions\.reveal\s*=\s*(?:[\w$.]*Never|0)/;
const NPX_EXECUTION_PATTERN = /\b(?:npx|npm\s+(?:exec|x))\b/i;
const GITHUB_SHA_REF_PATTERN = /github:([a-z0-9_.-]+\/[a-z0-9_.-]+)#([0-9a-f]{7,40}|\$\{[^}]+\})/i;
const COMMIT_SHA_PATTERN = /\b[0-9a-f]{40}\b/i;

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  const firstRow = matrix[0];
  if (!firstRow) return 0;
  for (let j = 0; j <= a.length; j++) {
    firstRow[j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    const currentRow = matrix[i];
    const prevRow = matrix[i - 1];
    if (!currentRow || !prevRow) continue;

    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        currentRow[j] = prevRow[j - 1] ?? 0;
      } else {
        currentRow[j] = Math.min(
          (prevRow[j - 1] ?? 0) + 1, // substitution
          (currentRow[j - 1] ?? 0) + 1, // insertion
          (prevRow[j] ?? 0) + 1, // deletion
        );
      }
    }
  }

  return matrix[b.length]?.[a.length] ?? 0;
}

function checkTyposquatting(pkgName: string): { target: string; distance: number } | null {
  const lowerName = pkgName.toLowerCase();

  // Skip known-good packages that are NOT typosquats
  if (KNOWN_GOOD_PACKAGES.has(lowerName)) {
    return null;
  }

  // First check known typosquats
  for (const [popular, typos] of POPULAR_PACKAGES) {
    if (typos.includes(lowerName)) {
      return { target: popular, distance: 1 };
    }
  }

  // Then check by edit distance for short package names
  for (const [popular] of POPULAR_PACKAGES) {
    // Only check if package name is similar length
    if (Math.abs(pkgName.length - popular.length) > 2) continue;

    const distance = levenshteinDistance(lowerName, popular);
    // Flag if edit distance is 1-2 and names are not identical
    if (distance > 0 && distance <= 2 && lowerName !== popular) {
      return { target: popular, distance };
    }
  }

  return null;
}

// --- Blocklist check ---

function matchesWildcard(extensionId: string, pattern: string): boolean {
  const lowerId = extensionId.toLowerCase();
  const lowerPattern = pattern.toLowerCase();

  if (lowerPattern.endsWith(".*")) {
    const prefix = lowerPattern.slice(0, -2);
    return lowerId.startsWith(prefix + ".");
  }
  return lowerId === lowerPattern;
}

export function checkBlocklist(manifest: VsixManifest, blocklist: BlocklistEntry[]): Finding[] {
  const findings: Finding[] = [];
  const extensionId = `${manifest.publisher}.${manifest.name}`;

  for (const entry of blocklist) {
    if (matchesWildcard(extensionId, entry.id)) {
      findings.push({
        id: "BLOCKLIST_MATCH",
        title: "Extension on malware blocklist",
        description: `Extension "${extensionId}" matches blocklisted pattern "${entry.id}": ${entry.reason}`,
        severity: "critical",
        category: "blocklist",
        location: {
          file: "package.json",
        },
        metadata: {
          campaign: entry.campaign,
          reference: entry.reference,
          blocklistEntry: entry.id,
        },
      });
    }
  }

  return findings;
}

// --- Manifest checks ---

export function checkActivationEvents(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];

  if (manifest.activationEvents?.includes("*")) {
    findings.push({
      id: "ACTIVATION_WILDCARD",
      title: "Extension activates on all events",
      description:
        'Extension uses "activationEvents": ["*"] which activates on every VS Code action. This is often used by malware to ensure immediate execution, but may be legitimate for extensions that need to respond to many different events.',
      severity: "high",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        legitimateUses: ["Extensions with many contribution points", "Global workspace tools"],
        redFlags: [
          "Simple extension with wildcard activation",
          "Combined with suspicious patterns",
        ],
      },
    });
  }

  if (manifest.activationEvents?.includes("onStartupFinished")) {
    findings.push({
      id: "ACTIVATION_STARTUP",
      title: "Extension activates on startup",
      description:
        'Extension uses "onStartupFinished" activation event. Common in extensions that need to initialize early (git integration, status bar items, language servers). Review if early activation is necessary for the extension\'s purpose.',
      severity: "medium",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        legitimateUses: [
          "Git integration",
          "Status bar extensions",
          "Language servers",
          "Background services",
        ],
        redFlags: [
          "Combined with network activity on startup",
          "No obvious need for early activation",
        ],
      },
    });
  }

  return findings;
}

export function checkThemeAbuse(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];
  const hasMain = Boolean(manifest.main || manifest.browser);
  const hasThemes =
    (manifest.contributes?.themes?.length ?? 0) > 0 ||
    (manifest.contributes?.iconThemes?.length ?? 0) > 0;

  if (hasThemes && hasMain) {
    findings.push({
      id: "THEME_WITH_CODE",
      title: "Theme extension has code entry point",
      description:
        "This extension contributes themes/icon themes but also has a code entry point (main/browser). Pure themes don't need executable code. However, some legitimate extensions combine themes with additional functionality (commands, settings sync).",
      severity: "high",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        main: manifest.main,
        browser: manifest.browser,
        themes: manifest.contributes?.themes?.length ?? 0,
        iconThemes: manifest.contributes?.iconThemes?.length ?? 0,
        legitimateUses: [
          "Theme packs with additional commands",
          "Theme switchers",
          "Theme previews",
        ],
        redFlags: [
          "Theme-only description but runs code",
          "Network activity from theme extension",
          "Known malware pattern",
        ],
      },
    });
  }

  return findings;
}

export function checkSuspiciousPermissions(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];

  const extensionDependencies = manifest["extensionDependencies"] as string[] | undefined;
  if (extensionDependencies) {
    for (const dep of extensionDependencies) {
      if (dep.includes("remote-ssh") || dep.includes("remote-wsl")) {
        findings.push({
          id: "REMOTE_DEPENDENCY",
          title: "Extension depends on remote access extension",
          description: `Extension depends on "${dep}" which provides remote system access. This is expected for extensions that enhance remote development workflows.`,
          severity: "medium",
          category: "manifest",
          location: {
            file: "package.json",
          },
          metadata: {
            dependency: dep,
            legitimateUses: [
              "Remote development helpers",
              "SSH workflow tools",
              "Container development",
            ],
            redFlags: [
              "No clear remote development purpose",
              "Combined with credential access patterns",
            ],
          },
        });
      }
    }
  }

  return findings;
}

// --- Dependency checks ---

export function checkMaliciousPackages(
  packageJson: PackageJson,
  maliciousPackages: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  // Only check runtime dependencies, not devDependencies
  // devDependencies aren't bundled in .vsix files and only used during development
  const deps = packageJson.dependencies ?? {};

  for (const pkgName of Object.keys(deps)) {
    if (maliciousPackages.has(pkgName.toLowerCase())) {
      findings.push({
        id: "MALICIOUS_NPM_PACKAGE",
        title: "Known malicious npm package",
        description: `Dependency "${pkgName}" is a known malicious npm package. This package has been identified in previous attacks and should be removed immediately.`,
        severity: "critical",
        category: "dependency",
        location: {
          file: "package.json",
        },
        metadata: {
          package: pkgName,
        },
      });
    }
  }

  return findings;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getStringField(record: Record<string, unknown>, field: string): string | null {
  const value = record[field];
  return typeof value === "string" ? value : null;
}

function isDevOnlyLockEntry(record: Record<string, unknown>, inheritedDev = false): boolean {
  return inheritedDev || record["dev"] === true || record["devOptional"] === true;
}

function packageNameFromNodeModulesPath(path: string): string | null {
  const marker = "node_modules/";
  const markerIndex = path.lastIndexOf(marker);
  if (markerIndex === -1) return null;

  const parts = path.slice(markerIndex + marker.length).split("/");
  const first = parts[0];
  if (!first) return null;

  if (first.startsWith("@")) {
    const second = parts[1];
    return second ? `${first}/${second}` : null;
  }

  return first;
}

function addPackageEvidence(
  evidenceByPackageVersion: Map<string, InstalledPackageEvidence>,
  evidence: InstalledPackageEvidence,
): void {
  const key = `${evidence.name.toLowerCase()}@${evidence.version}`;
  const existing = evidenceByPackageVersion.get(key);
  if (!existing || evidence.source === "bundled-node-module") {
    evidenceByPackageVersion.set(key, evidence);
  }
}

function collectPackageLockV1Dependencies(
  dependencies: Record<string, unknown>,
  source: "package-lock-v1" | "npm-shrinkwrap-v1",
  inheritedDev: boolean,
  evidence: InstalledPackageEvidence[],
): void {
  for (const [name, entry] of Object.entries(dependencies)) {
    if (!isRecord(entry)) continue;

    const devOnly = isDevOnlyLockEntry(entry, inheritedDev);
    const version = getStringField(entry, "version");
    if (!devOnly && version) {
      evidence.push({
        name: name.toLowerCase(),
        version,
        source,
        file: source === "package-lock-v1" ? "package-lock.json" : "npm-shrinkwrap.json",
      });
    }

    const nested = entry["dependencies"];
    if (isRecord(nested)) {
      collectPackageLockV1Dependencies(nested, source, devOnly, evidence);
    }
  }
}

function collectPackageLockEvidence(
  lockfileName: "package-lock.json" | "npm-shrinkwrap.json",
  content: string,
  findings: Finding[],
): InstalledPackageEvidence[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    findings.push({
      id: "PARSE_FAILURE_PACKAGE_LOCK",
      title: "Malformed npm lockfile",
      description:
        `${lockfileName} could not be parsed. ` +
        "Version-aware malicious npm package checks are skipped for this lockfile.",
      severity: "low",
      category: "pattern",
      location: { file: lockfileName },
      metadata: {
        error: error instanceof Error ? error.message : String(error),
      },
    });
    return [];
  }

  if (!isRecord(parsed)) return [];

  const evidence: InstalledPackageEvidence[] = [];
  const source: PackageVersionEvidenceSource =
    lockfileName === "package-lock.json" ? "package-lock" : "npm-shrinkwrap";

  const packages = parsed["packages"];
  if (isRecord(packages)) {
    for (const [path, entry] of Object.entries(packages)) {
      if (path === "" || !isRecord(entry) || isDevOnlyLockEntry(entry)) continue;

      const name = packageNameFromNodeModulesPath(path);
      const version = getStringField(entry, "version");
      if (!name || !version) continue;

      evidence.push({
        name: name.toLowerCase(),
        version,
        source,
        file: lockfileName,
      });
    }
  }

  const dependencies = parsed["dependencies"];
  if (isRecord(dependencies)) {
    collectPackageLockV1Dependencies(
      dependencies,
      lockfileName === "package-lock.json" ? "package-lock-v1" : "npm-shrinkwrap-v1",
      false,
      evidence,
    );
  }

  return evidence;
}

function collectBundledPackageEvidence(contents: VsixContents): InstalledPackageEvidence[] {
  const evidence: InstalledPackageEvidence[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!filename.includes("node_modules/") || !filename.endsWith("/package.json")) continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(getStringContent(contents, filename, buffer));
    } catch {
      continue;
    }

    if (!isRecord(parsed)) continue;

    const fallbackName = packageNameFromNodeModulesPath(filename);
    const name = getStringField(parsed, "name") ?? fallbackName;
    const version = getStringField(parsed, "version");
    if (!name || !version) continue;

    evidence.push({
      name: name.toLowerCase(),
      version,
      source: "bundled-node-module",
      file: filename,
    });
  }

  return evidence;
}

function collectInstalledPackageEvidence(
  contents: VsixContents,
  findings: Finding[],
): InstalledPackageEvidence[] {
  const evidenceByPackageVersion = new Map<string, InstalledPackageEvidence>();

  for (const lockfileName of ["package-lock.json", "npm-shrinkwrap.json"] as const) {
    const lockfile = contents.files.get(lockfileName);
    if (!lockfile) continue;

    const lockfileContent = getStringContent(contents, lockfileName, lockfile);
    for (const evidence of collectPackageLockEvidence(lockfileName, lockfileContent, findings)) {
      addPackageEvidence(evidenceByPackageVersion, evidence);
    }
  }

  for (const evidence of collectBundledPackageEvidence(contents)) {
    addPackageEvidence(evidenceByPackageVersion, evidence);
  }

  return [...evidenceByPackageVersion.values()];
}

export function checkMaliciousPackageVersions(
  contents: VsixContents,
  maliciousVersionAdvisories: Map<string, MaliciousNpmVersionAdvisory[]>,
): Finding[] {
  const findings: Finding[] = [];
  if (maliciousVersionAdvisories.size === 0) return findings;

  for (const installed of collectInstalledPackageEvidence(contents, findings)) {
    const advisories = maliciousVersionAdvisories.get(installed.name);
    if (!advisories) continue;

    for (const advisory of advisories) {
      if (!advisory.affectedVersions.includes(installed.version)) continue;

      findings.push({
        id: "MALICIOUS_NPM_PACKAGE_VERSION",
        title: "Known malicious npm package version",
        description:
          `Dependency "${installed.name}" resolves to known malicious version ` +
          `${installed.version} (${advisory.advisory}): ${advisory.reason}.`,
        severity: "critical",
        category: "dependency",
        location: {
          file: installed.file,
        },
        metadata: {
          package: installed.name,
          version: installed.version,
          advisory: advisory.advisory,
          campaign: advisory.campaign,
          references: advisory.references,
          evidenceSource: installed.source,
          matched: `${installed.name}@${installed.version}`,
          redFlags: [
            "Exact resolved version matches a known malicious npm release",
            "Legitimate package name was compromised at this specific version",
          ],
        },
      });
    }
  }

  return findings;
}

export function checkTyposquattingPackages(packageJson: PackageJson): Finding[] {
  const findings: Finding[] = [];
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  for (const pkgName of Object.keys(allDeps)) {
    const typosquat = checkTyposquatting(pkgName);
    if (typosquat) {
      findings.push({
        id: "TYPOSQUAT_PACKAGE",
        title: "Potential typosquatting package",
        description: `Dependency "${pkgName}" is suspiciously similar to popular package "${typosquat.target}" (edit distance: ${typosquat.distance}). This may be a typosquatting attack.`,
        severity: "high",
        category: "dependency",
        location: {
          file: "package.json",
        },
        metadata: {
          package: pkgName,
          similar_to: typosquat.target,
          edit_distance: typosquat.distance,
        },
      });
    }
  }

  return findings;
}

export function checkLifecycleScripts(packageJson: PackageJson): Finding[] {
  const findings: Finding[] = [];
  const scripts = packageJson.scripts ?? {};

  for (const scriptName of DANGEROUS_SCRIPTS) {
    const scriptContent = scripts[scriptName];
    if (!scriptContent) continue;

    // Check for malicious patterns in the script
    for (const { pattern, desc } of MALICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(scriptContent)) {
        findings.push({
          id: "MALICIOUS_LIFECYCLE_SCRIPT",
          title: `Suspicious ${scriptName} script`,
          description: `The ${scriptName} script contains suspicious content: ${desc}. Lifecycle scripts run automatically during npm install and can execute arbitrary code.`,
          severity: "critical",
          category: "dependency",
          location: {
            file: "package.json",
          },
          metadata: {
            script: scriptName,
            content: scriptContent.slice(0, 200),
            pattern: desc,
          },
        });
        break; // Only report one pattern per script
      }
    }

    // Also flag any lifecycle script that exists even without malicious patterns
    // as they're a common attack vector
    if (
      !findings.some(
        (f) => f.id === "MALICIOUS_LIFECYCLE_SCRIPT" && f.metadata?.["script"] === scriptName,
      )
    ) {
      findings.push({
        id: "LIFECYCLE_SCRIPT",
        title: `Has ${scriptName} script`,
        description: `The extension has a ${scriptName} script that runs during installation. While not always malicious, lifecycle scripts are a common attack vector. Review the script content carefully.`,
        severity: "medium",
        category: "dependency",
        location: {
          file: "package.json",
        },
        metadata: {
          script: scriptName,
          content: scriptContent.slice(0, 200),
        },
      });
    }
  }

  return findings;
}

export function checkExecutionPatterns(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const startupExecutionFiles: Array<{ filename: string; line?: number; kind: string }> = [];
  const startsOnStartup =
    contents.manifest.activationEvents?.includes("onStartupFinished") ?? false;

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = getStringContent(contents, filename, buffer);
    const lineStarts = computeLineStarts(content);

    const taskExecutionMatch = TASK_EXECUTION_PATTERN.exec(content);
    const taskConstructionMatch = TASK_CONSTRUCTION_PATTERN.exec(content);
    const shellExecutionMatch = SHELL_EXECUTION_PATTERN.exec(content);
    const githubRefMatch = GITHUB_SHA_REF_PATTERN.exec(content);
    const launchesTask =
      taskExecutionMatch !== null &&
      (taskConstructionMatch !== null || shellExecutionMatch !== null);
    const launchesProcess = launchesTask || PROCESS_LAUNCH_PATTERN.test(content);

    if (launchesTask && HIDDEN_TASK_PATTERN.test(content)) {
      const taskAnchor = taskExecutionMatch ?? taskConstructionMatch ?? shellExecutionMatch;
      const line =
        taskAnchor?.index !== undefined
          ? findLineNumberByIndex(content, taskAnchor.index, lineStarts)
          : undefined;
      findings.push({
        id: "BACKGROUND_TASK_EXECUTION",
        title: "Hidden VS Code task execution",
        description:
          `File "${filename}" creates and executes a VS Code task while suppressing task UI. ` +
          "This is a strong indicator of background command execution.",
        severity: "high",
        category: "pattern",
        location: line !== undefined ? { file: filename, line } : { file: filename },
        metadata: {
          hiddenTask: true,
        },
      });
    }

    if (NPX_EXECUTION_PATTERN.test(content) && githubRefMatch?.index !== undefined) {
      const repo = githubRefMatch[1];
      const ref = githubRefMatch[2];
      const isInterpolatedRef = ref?.startsWith("${") ?? false;
      const hasCommitSha = !isInterpolatedRef || COMMIT_SHA_PATTERN.test(content);

      if (repo && ref && hasCommitSha) {
        const line = findLineNumberByIndex(content, githubRefMatch.index, lineStarts);
        findings.push({
          id: "GITHUB_SHA_EXECUTION",
          title: "Executes npx/npm command from GitHub commit",
          description:
            `File "${filename}" executes an npx/npm command against ` +
            `github:${repo}#${isInterpolatedRef ? "…" : ref}. Running code directly from ` +
            "a GitHub commit inside extension runtime is highly suspicious.",
          severity: "critical",
          category: "pattern",
          location: { file: filename, line },
          metadata: {
            repo,
            ref: isInterpolatedRef ? "interpolated" : ref,
            command: githubRefMatch[0],
          },
        });
      }
    }

    if (startsOnStartup && launchesProcess) {
      const anchor = taskExecutionMatch ?? shellExecutionMatch;
      const line =
        anchor?.index !== undefined
          ? findLineNumberByIndex(content, anchor.index, lineStarts)
          : undefined;
      startupExecutionFiles.push(
        line !== undefined
          ? {
              filename,
              line,
              kind: launchesTask ? "task" : "process",
            }
          : {
              filename,
              kind: launchesTask ? "task" : "process",
            },
      );
    }
  }

  const startupExecution =
    startupExecutionFiles.find((entry) => entry.kind === "task") ?? startupExecutionFiles[0];
  if (startsOnStartup && startupExecution) {
    findings.push({
      id: "STARTUP_EXECUTION_CHAIN",
      title: "Startup activation triggers command execution",
      description:
        `Extension activates on "onStartupFinished" and ${startupExecution.kind}-launches ` +
        `from "${startupExecution.filename}". This combination materially raises the risk ` +
        "of unattended code execution at editor startup.",
      severity: "high",
      category: "manifest",
      location:
        startupExecution.line !== undefined
          ? { file: startupExecution.filename, line: startupExecution.line }
          : { file: startupExecution.filename },
      metadata: {
        activationEvent: "onStartupFinished",
        executionKind: startupExecution.kind,
      },
    });
  }

  return findings;
}

// --- Main export ---

function parsePackageJson(contents: VsixContents): PackageJson | Finding | null {
  const packageJsonBuffer = contents.files.get("package.json");
  if (!packageJsonBuffer) {
    return null;
  }

  try {
    return JSON.parse(getStringContent(contents, "package.json", packageJsonBuffer)) as PackageJson;
  } catch (error) {
    return {
      id: "PARSE_FAILURE_PACKAGE",
      title: "Malformed package.json",
      description:
        "package.json could not be parsed. " +
        "Dependency and package intelligence checks are skipped " +
        "for this extension.",
      severity: "low",
      category: "pattern",
      location: { file: "package.json" },
      metadata: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

export function checkManifest(contents: VsixContents): Finding[] {
  const { manifest } = contents;
  const findings: Finding[] = [];

  findings.push(...checkActivationEvents(manifest));
  findings.push(...checkThemeAbuse(manifest));
  findings.push(...checkSuspiciousPermissions(manifest));

  return findings;
}

export function checkDependencyHeuristics(contents: VsixContents): Finding[] {
  const parsed = parsePackageJson(contents);
  if (!parsed) return [];
  if ("id" in parsed) return [parsed];

  return [...checkTyposquattingPackages(parsed), ...checkLifecycleScripts(parsed)];
}

export function checkPackageIntel(contents: VsixContents, zooData: ZooData): Finding[] {
  const findings: Finding[] = [];

  findings.push(...checkBlocklist(contents.manifest, zooData.blocklist));
  findings.push(...checkMaliciousPackageVersions(contents, zooData.maliciousNpmVersions));

  const parsed = parsePackageJson(contents);
  if (!parsed) return findings;
  if ("id" in parsed) return [...findings, parsed];

  findings.push(...checkMaliciousPackages(parsed, zooData.maliciousNpmPackages));

  return findings;
}

export function checkPackage(contents: VsixContents, zooData: ZooData): Finding[] {
  const findings: Finding[] = [];

  findings.push(...checkManifest(contents));
  findings.push(...checkExecutionPatterns(contents));
  findings.push(...checkBlocklist(contents.manifest, zooData.blocklist));
  findings.push(...checkMaliciousPackageVersions(contents, zooData.maliciousNpmVersions));

  const parsed = parsePackageJson(contents);
  if (!parsed) return findings;
  if ("id" in parsed) return [...findings, parsed];

  findings.push(...checkMaliciousPackages(parsed, zooData.maliciousNpmPackages));
  findings.push(...checkTyposquattingPackages(parsed));
  findings.push(...checkLifecycleScripts(parsed));

  return findings;
}
