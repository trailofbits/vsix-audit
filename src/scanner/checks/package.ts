import type { BlocklistEntry, Finding, VsixContents, VsixManifest, ZooData } from "../types.js";

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
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

// --- Main export ---

export function checkPackage(contents: VsixContents, zooData: ZooData): Finding[] {
  const { manifest } = contents;
  const findings: Finding[] = [];

  // Blocklist check
  findings.push(...checkBlocklist(manifest, zooData.blocklist));

  // Manifest checks (use manifest object directly)
  findings.push(...checkActivationEvents(manifest));
  findings.push(...checkThemeAbuse(manifest));
  findings.push(...checkSuspiciousPermissions(manifest));

  // Dependencies checks (parse package.json from files)
  const packageJsonBuffer = contents.files.get("package.json");
  if (packageJsonBuffer) {
    let packageJson: PackageJson;
    try {
      packageJson = JSON.parse(packageJsonBuffer.toString("utf8")) as PackageJson;
    } catch (error) {
      findings.push({
        id: "PARSE_FAILURE_PACKAGE",
        title: "Malformed package.json",
        description:
          "package.json could not be parsed. " +
          "All dependency checks (typosquatting, " +
          "lifecycle scripts, blocklist) are skipped " +
          "for this extension.",
        severity: "low",
        category: "pattern",
        location: { file: "package.json" },
        metadata: {
          error: error instanceof Error ? error.message : String(error),
        },
      });
      return findings;
    }

    findings.push(...checkMaliciousPackages(packageJson, zooData.maliciousNpmPackages));
    findings.push(...checkTyposquattingPackages(packageJson));
    findings.push(...checkLifecycleScripts(packageJson));
  }

  return findings;
}
