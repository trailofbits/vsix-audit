import type { Finding, VsixContents, ZooData } from "../types.js";

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

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

export function checkMaliciousPackages(
  packageJson: PackageJson,
  maliciousPackages: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  for (const pkgName of Object.keys(allDeps)) {
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

export function checkDependencies(contents: VsixContents, zooData: ZooData): Finding[] {
  const findings: Finding[] = [];

  // Parse package.json from the extension
  const packageJsonBuffer = contents.files.get("package.json");
  if (!packageJsonBuffer) {
    return findings;
  }

  let packageJson: PackageJson;
  try {
    packageJson = JSON.parse(packageJsonBuffer.toString("utf8")) as PackageJson;
  } catch {
    return findings;
  }

  findings.push(...checkMaliciousPackages(packageJson, zooData.maliciousNpmPackages));
  findings.push(...checkTyposquattingPackages(packageJson));
  findings.push(...checkLifecycleScripts(packageJson));

  return findings;
}
