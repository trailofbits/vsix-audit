import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import { findLineNumberByIndex } from "../utils.js";

/**
 * Behavioral signatures detect multi-stage attack patterns.
 * Unlike simple pattern matching, these look for combinations of
 * behaviors that together indicate malicious activity.
 */

type ActionType =
  | "file_read"
  | "encode"
  | "network"
  | "exec"
  | "env_access"
  | "persistence"
  | "download"
  | "clipboard";

interface BehaviorStage {
  action: ActionType;
  patterns: RegExp[];
  description: string;
}

interface BehavioralSignature {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  stages: BehaviorStage[];
  /** Minimum stages that must match (default: all) */
  minStages?: number;
  /** Maximum distance between first and last stage (default: 3000 chars) */
  maxSpan?: number;
  legitimateUses?: string[];
  redFlags?: string[];
}

interface StageMatch {
  stage: BehaviorStage;
  index: number;
  matched: string;
}

const SIGNATURES: BehavioralSignature[] = [
  {
    id: "BEHAVIOR_CREDENTIAL_EXFIL",
    title: "Credential exfiltration pattern",
    description:
      "Code reads sensitive files, encodes the content, and sends it to an external server. This is the classic credential theft attack chain.",
    severity: "critical",
    stages: [
      {
        action: "file_read",
        patterns: [
          /readFile(?:Sync)?\s*\(/gi,
          /fs\.promises\.readFile/gi,
          /createReadStream\s*\(/gi,
        ],
        description: "File read operation",
      },
      {
        action: "encode",
        patterns: [
          /Buffer\.from\s*\([^)]+\)\.toString\s*\(\s*['"]base64/gi,
          /btoa\s*\(/gi,
          /\.toString\s*\(\s*['"](?:base64|hex)['"]\s*\)/gi,
          /JSON\.stringify\s*\(/gi,
        ],
        description: "Data encoding for transmission",
      },
      {
        action: "network",
        patterns: [
          /fetch\s*\(/gi,
          /axios\./gi,
          /https?\.request/gi,
          /\.post\s*\(/gi,
          /\.send\s*\(/gi,
        ],
        description: "Network transmission",
      },
    ],
    redFlags: [
      "Reads from home directory or .ssh",
      "Encodes before sending",
      "Sends to external domain",
    ],
  },
  {
    id: "BEHAVIOR_REVERSE_SHELL",
    title: "Reverse shell pattern",
    description:
      "Code establishes network connection and pipes input to command execution. This creates a remote shell for attackers.",
    severity: "critical",
    stages: [
      {
        action: "network",
        patterns: [
          /net\.Socket/gi,
          /net\.connect/gi,
          /net\.createConnection/gi,
          /new\s+WebSocket/gi,
        ],
        description: "Network connection",
      },
      {
        action: "exec",
        patterns: [/child_process/gi, /\.spawn\s*\(/gi, /\.exec\s*\(/gi, /process\.stdin/gi],
        description: "Command execution",
      },
    ],
    maxSpan: 1500,
    redFlags: ["Socket piped to shell", "Remote command execution"],
  },
  {
    id: "BEHAVIOR_SUPPLY_CHAIN_ATTACK",
    title: "Install script attack pattern",
    description:
      "Package lifecycle script accesses environment, executes commands, and phones home. This is a supply chain attack pattern.",
    severity: "high", // Downgraded - common in legitimate build tools
    stages: [
      {
        action: "env_access",
        patterns: [
          /os\.homedir\s*\(\)/gi,
          /os\.userInfo\s*\(\)/gi,
          /process\.env\.(?:HOME|USERPROFILE|APPDATA)/gi,
        ],
        description: "Home directory access",
      },
      {
        action: "exec",
        patterns: [/child_process\.exec\s*\(/gi, /execSync\s*\(/gi, /spawnSync\s*\(/gi],
        description: "Command execution",
      },
      {
        action: "network",
        patterns: [/fetch\s*\(/gi, /axios\s*\./gi, /curl\s+/gi, /wget\s+/gi],
        description: "Network activity",
      },
    ],
    minStages: 3, // Require all 3 stages to reduce false positives
    maxSpan: 1000, // Tighter proximity requirement
    legitimateUses: ["Build scripts", "Development tools"],
    redFlags: ["Runs in postinstall", "Collects system info", "Sends to unknown domain"],
  },
  {
    id: "BEHAVIOR_DROPPER",
    title: "Malware dropper pattern",
    description:
      "Code downloads content from remote URL, writes it to file, and executes it. This is a dropper/downloader pattern.",
    severity: "critical",
    stages: [
      {
        action: "download",
        patterns: [
          /fetch\s*\([^)]*https?:\/\//gi,
          /axios\.get\s*\([^)]*https?:\/\//gi,
          /https?\.get\s*\(/gi,
          /request\s*\([^)]*https?:\/\//gi,
        ],
        description: "Remote content download",
      },
      {
        action: "file_read",
        patterns: [
          /writeFile(?:Sync)?\s*\(/gi,
          /createWriteStream\s*\(/gi,
          /fs\.promises\.writeFile/gi,
        ],
        description: "File write",
      },
      {
        action: "exec",
        patterns: [/child_process/gi, /\.exec\s*\(/gi, /\.spawn\s*\(/gi, /execSync/gi],
        description: "Execution",
      },
    ],
    maxSpan: 2000,
    redFlags: [
      "Downloads executable",
      "Writes to temp or hidden location",
      "Executes downloaded content",
    ],
  },
  {
    id: "BEHAVIOR_KEYLOGGER",
    title: "Keystroke capture pattern",
    description:
      "Code captures keyboard/input events and stores or transmits the data. This indicates keylogging behavior.",
    severity: "high",
    stages: [
      {
        action: "clipboard",
        patterns: [
          // onDidChangeTextDocument is legitimate for language servers - don't flag it
          // Instead, look for actual keystroke monitoring
          /keyboard.*event/gi,
          /keydown|keyup|keypress/gi,
          /clipboard\.readText/gi,
          /getSelection\s*\(\s*\)\.toString/gi,
        ],
        description: "Keystroke/clipboard capture",
      },
      {
        action: "persistence",
        patterns: [
          /globalState\.update/gi,
          /writeFileSync?\s*\([^)]*keystroke/gi,
          /localStorage\.setItem/gi,
        ],
        description: "Data storage",
      },
      {
        action: "network",
        patterns: [/discord\.com\/api\/webhooks/gi, /discordapp\.com\/api\/webhooks/gi],
        description: "Data exfiltration to Discord",
      },
    ],
    minStages: 2,
    legitimateUses: ["Keyboard shortcut extensions"],
    redFlags: ["Captures all keystrokes", "Sends to Discord webhook", "No user consent mechanism"],
  },
  {
    id: "BEHAVIOR_CRYPTO_STEALER",
    title: "Cryptocurrency stealer pattern",
    description: "Code scans for wallet files, extracts keys/seeds, and exfiltrates them.",
    severity: "critical",
    stages: [
      {
        action: "file_read",
        patterns: [
          /\.ethereum/gi,
          /\.bitcoin/gi,
          /wallet\.dat/gi,
          /keystore/gi,
          /seed.*phrase/gi,
          /mnemonic/gi,
        ],
        description: "Wallet file access",
      },
      {
        action: "encode",
        patterns: [
          /btoa\s*\(/gi, // More specific - require function call
          /Buffer\.from\s*\([^)]*\)\.toString\s*\(\s*['"]base64/gi,
          /toString\s*\(\s*['"](?:base64|hex)['"]\s*\)/gi,
        ],
        description: "Data encoding for exfil",
      },
      {
        action: "network",
        patterns: [/discord.*webhook/gi, /\.post\s*\([^)]*wallet/gi],
        description: "Exfiltration",
      },
    ],
    // Require all 3 stages - wallet access is the key indicator
    minStages: 3,
    maxSpan: 1500,
    redFlags: [
      "Scans for multiple wallet types",
      "Extracts private keys",
      "Sends to Discord/external",
    ],
  },
  {
    id: "BEHAVIOR_PERSISTENCE",
    title: "Persistence mechanism pattern",
    description:
      "Code modifies startup files, schedules tasks, or installs itself for persistence.",
    severity: "high",
    stages: [
      {
        action: "file_read",
        patterns: [
          /\.bashrc/gi,
          /\.zshrc/gi,
          /\.profile/gi,
          /crontab/gi,
          /startup/gi,
          /autostart/gi,
        ],
        description: "Startup file access",
      },
      {
        action: "persistence",
        patterns: [/writeFile/gi, /appendFile/gi, /fs\.promises\.writeFile/gi],
        description: "File modification",
      },
    ],
    legitimateUses: ["Shell configuration tools", "Development environment setup"],
    redFlags: ["Writes to startup files", "Adds hidden entries", "No user interaction"],
  },
  {
    id: "BEHAVIOR_SELF_PROPAGATION",
    title: "Self-propagation pattern",
    description:
      "Code accesses package publishing credentials and attempts to publish itself. This is worm-like behavior.",
    severity: "critical",
    stages: [
      {
        action: "file_read",
        patterns: [/\.npmrc/gi, /NPM_TOKEN/gi, /OPENVSX_TOKEN/gi, /npm\s+config/gi],
        description: "Publishing credential access",
      },
      {
        action: "exec",
        patterns: [/npm\s+publish/gi, /vsce\s+publish/gi, /ovsx\s+publish/gi, /yarn\s+publish/gi],
        description: "Package publishing",
      },
    ],
    redFlags: ["Accesses publish tokens", "Runs publish commands", "GlassWorm-style worm"],
  },
];

/**
 * Find all matches for patterns in content
 */
function findPatternMatches(
  content: string,
  patterns: RegExp[],
): { index: number; matched: string }[] {
  const matches: { index: number; matched: string }[] = [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      matches.push({
        index: match.index,
        matched: match[0].slice(0, 60),
      });
    }
  }

  return matches;
}

/**
 * Check if a signature matches in the content
 */
function checkSignature(content: string, signature: BehavioralSignature): StageMatch[] | null {
  const stageMatches: StageMatch[] = [];
  const minStages = signature.minStages ?? signature.stages.length;
  const maxSpan = signature.maxSpan ?? 3000;

  // Find matches for each stage
  for (const stage of signature.stages) {
    const matches = findPatternMatches(content, stage.patterns);
    if (matches.length > 0) {
      const firstMatch = matches[0];
      if (firstMatch) {
        stageMatches.push({
          stage,
          index: firstMatch.index,
          matched: firstMatch.matched,
        });
      }
    }
  }

  // Check if enough stages matched
  if (stageMatches.length < minStages) {
    return null;
  }

  // Check if stages are within maxSpan
  if (stageMatches.length > 1) {
    const indices = stageMatches.map((m) => m.index);
    const span = Math.max(...indices) - Math.min(...indices);
    if (span > maxSpan) {
      return null;
    }
  }

  return stageMatches;
}

export function checkBehavioral(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = buffer.toString("utf8");

    for (const signature of SIGNATURES) {
      const stageMatches = checkSignature(content, signature);
      if (!stageMatches) continue;

      // Deduplicate
      const key = `${signature.id}:${filename}`;
      if (seenFindings.has(key)) continue;
      seenFindings.add(key);

      const firstMatch = stageMatches[0];
      if (!firstMatch) continue;

      findings.push({
        id: signature.id,
        title: signature.title,
        description: signature.description,
        severity: signature.severity,
        category: "behavioral",
        location: {
          file: filename,
          line: findLineNumberByIndex(content, firstMatch.index),
        },
        metadata: {
          stagesMatched: stageMatches.length,
          totalStages: signature.stages.length,
          stages: stageMatches.map((m) => ({
            action: m.stage.action,
            description: m.stage.description,
            matched: m.matched,
            line: findLineNumberByIndex(content, m.index),
          })),
          ...(signature.legitimateUses && {
            legitimateUses: signature.legitimateUses,
          }),
          ...(signature.redFlags && { redFlags: signature.redFlags }),
        },
      });
    }
  }

  return findings;
}
