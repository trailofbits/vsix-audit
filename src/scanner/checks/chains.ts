import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import { findLineNumberByIndex } from "../utils.js";

/**
 * Unified chain detection for multi-stage attack patterns.
 *
 * This module consolidates DataFlow (2-stage source→sink) and Behavioral (N-stage)
 * detection into a single framework. Both share the same mechanics:
 * - Find pattern matches across stages
 * - Check proximity/span constraints
 * - Deduplicate findings
 */

export interface ChainStage {
  id: string;
  name: string;
  patterns: RegExp[];
}

export interface ChainRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  stages: ChainStage[];
  constraints: {
    /** Minimum stages that must match (default: all) */
    minStages?: number;
    /** Maximum distance between first and last stage match (default: 3000 chars) */
    maxSpan?: number;
  };
  legitimateUses?: string[];
  redFlags?: string[];
}

interface StageMatch {
  stageId: string;
  stageName: string;
  index: number;
  matched: string;
}

// =============================================================================
// Stage Definitions (sources, sinks, and behavioral actions)
// =============================================================================

const STAGES: Record<string, ChainStage> = {
  // Sources (where sensitive data originates)
  SSH_KEYS: {
    id: "SSH_KEYS",
    name: "SSH private keys",
    patterns: [
      /\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)/gi,
      /\.ssh\/config/gi,
      /BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/gi,
      /BEGIN\s+OPENSSH\s+PRIVATE\s+KEY/gi,
      /(?:fs|promises?)\.readFile(?:Sync)?\s*\([^)]*\.ssh/gi,
      /readFile(?:Sync)?\s*\([^)]*id_(?:rsa|ed25519)/gi,
    ],
  },
  CRYPTO_WALLETS: {
    id: "CRYPTO_WALLETS",
    name: "Cryptocurrency wallets",
    patterns: [
      /\.ethereum/gi,
      /\.bitcoin/gi,
      /wallet\.dat/gi,
      /keystore\/[a-z0-9-]+/gi,
      /solana\/id\.json/gi,
      /Exodus/gi,
      /MetaMask/gi,
      /phantom/gi,
      /readFile(?:Sync)?\s*\([^)]*(?:wallet|ethereum|bitcoin|keystore)/gi,
      /readFile(?:Sync)?\s*\([^)]*\.solana/gi,
      /seed.*phrase/gi,
      /mnemonic/gi,
    ],
  },
  CREDENTIALS: {
    id: "CREDENTIALS",
    name: "Credential files",
    patterns: [
      /\.env(?:\.local|\.production)?/gi,
      /\.npmrc/gi,
      /\.netrc/gi,
      /\.git-credentials/gi,
      /credentials\.json/gi,
      /secrets?\./gi,
      /readFile(?:Sync)?\s*\([^)]*\.env/gi,
      /readFile(?:Sync)?\s*\([^)]*\.npmrc/gi,
      /process\.env\.[A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/gi,
    ],
  },
  BROWSER_DATA: {
    id: "BROWSER_DATA",
    name: "Browser stored data",
    patterns: [
      /Google[/\\]Chrome[/\\].*Login\s+Data/gi,
      /Google[/\\]Chrome[/\\].*Cookies/gi,
      /Mozilla[/\\]Firefox[/\\].*logins\.json/gi,
      /BraveSoftware[/\\].*Login\s+Data/gi,
      /Microsoft[/\\]Edge[/\\].*Login\s+Data/gi,
      /Local\s+Storage[/\\]leveldb/gi,
      /readFile(?:Sync)?\s*\([^)]*(?:Chrome|Firefox|Edge|Brave)/gi,
      /readFile(?:Sync)?\s*\([^)]*Login\s*Data/gi,
    ],
  },
  API_TOKENS: {
    id: "API_TOKENS",
    name: "API tokens and keys",
    patterns: [
      /(?:GITHUB|GITLAB|BITBUCKET)_(?:TOKEN|API_KEY)/gi,
      /NPM_TOKEN/gi,
      /OPENVSX_(?:TOKEN|PAT)/gi,
      /(?:AWS|AZURE|GCP)_(?:ACCESS_KEY|SECRET|TOKEN)/gi,
      /OPENAI_API_KEY/gi,
      /ANTHROPIC_API_KEY/gi,
      /process\.env\.(?:GITHUB|GITLAB|NPM|AWS|AZURE|OPENAI|ANTHROPIC)/gi,
    ],
  },

  // Sinks (where data leaves or gets executed)
  NETWORK_SEND: {
    id: "NETWORK_SEND",
    name: "Network transmission",
    patterns: [
      /fetch\s*\([^)]*,\s*\{[^}]*method\s*:\s*['"](?:POST|PUT)/gi,
      /axios\.(?:post|put)\s*\(/gi,
      /https?\.request\s*\([^)]*method\s*:\s*['"](?:POST|PUT)/gi,
      /request\.(?:post|put)\s*\(/gi,
      /got\.(?:post|put)\s*\(/gi,
      /superagent\.(?:post|put)\s*\(/gi,
    ],
  },
  WEBSOCKET_SEND: {
    id: "WEBSOCKET_SEND",
    name: "WebSocket transmission",
    patterns: [/\.send\s*\([^)]+\)/gi, /WebSocket\s*\([^)]*\)/gi, /ws\.send\s*\(/gi],
  },
  DISCORD_WEBHOOK: {
    id: "DISCORD_WEBHOOK",
    name: "Discord webhook",
    patterns: [/discord\.com\/api\/webhooks/gi, /discordapp\.com\/api\/webhooks/gi],
  },
  EVAL_EXEC: {
    id: "EVAL_EXEC",
    name: "Code execution",
    patterns: [
      /\beval\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /\(\s*\)\s*\[\s*['"]constructor['"]\s*\]/gi,
    ],
  },
  CHILD_PROCESS: {
    id: "CHILD_PROCESS",
    name: "Shell execution",
    patterns: [
      /child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/gi,
      /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\$\{/gi,
    ],
  },

  // Behavioral stages
  FILE_READ: {
    id: "FILE_READ",
    name: "File read operation",
    patterns: [/readFile(?:Sync)?\s*\(/gi, /fs\.promises\.readFile/gi, /createReadStream\s*\(/gi],
  },
  FILE_WRITE: {
    id: "FILE_WRITE",
    name: "File write operation",
    patterns: [
      /writeFile(?:Sync)?\s*\(/gi,
      /createWriteStream\s*\(/gi,
      /fs\.promises\.writeFile/gi,
      /appendFile/gi,
    ],
  },
  ENCODE: {
    id: "ENCODE",
    name: "Data encoding",
    patterns: [
      /Buffer\.from\s*\([^)]+\)\.toString\s*\(\s*['"]base64/gi,
      /btoa\s*\(/gi,
      /\.toString\s*\(\s*['"](?:base64|hex)['"]\s*\)/gi,
      /JSON\.stringify\s*\(/gi,
    ],
  },
  NETWORK: {
    id: "NETWORK",
    name: "Network activity",
    patterns: [
      /fetch\s*\(/gi,
      /axios\./gi,
      /https?\.request/gi,
      /\.post\s*\(/gi,
      /\.send\s*\(/gi,
      /net\.Socket/gi,
      /net\.connect/gi,
      /net\.createConnection/gi,
      /new\s+WebSocket/gi,
    ],
  },
  EXEC: {
    id: "EXEC",
    name: "Command execution",
    patterns: [
      /child_process/gi,
      /\.spawn\s*\(/gi,
      /\.exec\s*\(/gi,
      /process\.stdin/gi,
      /execSync/gi,
      /spawnSync/gi,
    ],
  },
  ENV_ACCESS: {
    id: "ENV_ACCESS",
    name: "Environment access",
    patterns: [
      /os\.homedir\s*\(\)/gi,
      /os\.userInfo\s*\(\)/gi,
      /process\.env\.(?:HOME|USERPROFILE|APPDATA)/gi,
    ],
  },
  DOWNLOAD: {
    id: "DOWNLOAD",
    name: "Remote download",
    patterns: [
      /fetch\s*\([^)]*https?:\/\//gi,
      /axios\.get\s*\([^)]*https?:\/\//gi,
      /https?\.get\s*\(/gi,
      /request\s*\([^)]*https?:\/\//gi,
      /curl\s+/gi,
      /wget\s+/gi,
    ],
  },
  CLIPBOARD: {
    id: "CLIPBOARD",
    name: "Keystroke/clipboard capture",
    patterns: [
      /keyboard.*event/gi,
      /keydown|keyup|keypress/gi,
      /clipboard\.readText/gi,
      /getSelection\s*\(\s*\)\.toString/gi,
    ],
  },
  PERSISTENCE: {
    id: "PERSISTENCE",
    name: "Persistence storage",
    patterns: [
      /globalState\.update/gi,
      /writeFileSync?\s*\([^)]*keystroke/gi,
      /localStorage\.setItem/gi,
    ],
  },
  STARTUP_FILE: {
    id: "STARTUP_FILE",
    name: "Startup file access",
    patterns: [/\.bashrc/gi, /\.zshrc/gi, /\.profile/gi, /crontab/gi, /startup/gi, /autostart/gi],
  },
  PUBLISH_CREDS: {
    id: "PUBLISH_CREDS",
    name: "Publishing credentials",
    patterns: [/\.npmrc/gi, /NPM_TOKEN/gi, /OPENVSX_TOKEN/gi, /npm\s+config/gi],
  },
  PUBLISH_CMD: {
    id: "PUBLISH_CMD",
    name: "Package publishing",
    patterns: [/npm\s+publish/gi, /vsce\s+publish/gi, /ovsx\s+publish/gi, /yarn\s+publish/gi],
  },
};

// =============================================================================
// Chain Rules (combining stages into detection patterns)
// =============================================================================

const CHAIN_RULES: ChainRule[] = [
  // DataFlow-style rules (2-stage: source → sink)
  {
    id: "FLOW_SSH_KEY_EXFIL",
    title: "SSH key exfiltration pattern",
    description:
      "Code reads SSH private keys and sends data over network. This is a credential theft pattern.",
    severity: "critical",
    stages: [STAGES["SSH_KEYS"]!, STAGES["NETWORK_SEND"]!],
    constraints: { maxSpan: 2000 },
    redFlags: ["Reads .ssh directory", "Sends to external URL"],
  },
  {
    id: "FLOW_WALLET_EXFIL",
    title: "Cryptocurrency wallet exfiltration",
    description:
      "Code accesses cryptocurrency wallet data and sends it over network. This is a crypto theft pattern.",
    severity: "critical",
    stages: [STAGES["CRYPTO_WALLETS"]!, STAGES["NETWORK_SEND"]!],
    constraints: { maxSpan: 2000 },
    redFlags: ["Accesses wallet files", "Sends to external server"],
  },
  {
    id: "FLOW_CRED_EXFIL",
    title: "Credential exfiltration pattern",
    description: "Code reads credential files (.env, .npmrc, etc.) and sends data over network.",
    severity: "critical",
    stages: [STAGES["CREDENTIALS"]!, STAGES["NETWORK_SEND"]!],
    constraints: { maxSpan: 2000 },
    redFlags: ["Reads environment files", "HTTP POST to external"],
  },
  {
    id: "FLOW_BROWSER_EXFIL",
    title: "Browser data exfiltration",
    description: "Code accesses browser stored passwords/cookies and sends them over network.",
    severity: "critical",
    stages: [STAGES["BROWSER_DATA"]!, STAGES["NETWORK_SEND"]!],
    constraints: { maxSpan: 2000 },
    redFlags: ["Reads Chrome/Firefox data", "Network exfiltration"],
  },
  {
    id: "FLOW_TOKEN_EXFIL",
    title: "API token exfiltration",
    description: "Code accesses API tokens from environment and sends them to external server.",
    severity: "critical",
    stages: [STAGES["API_TOKENS"]!, STAGES["NETWORK_SEND"]!],
    constraints: { maxSpan: 2000 },
    legitimateUses: ["Token validation services", "OAuth flows"],
    redFlags: ["Tokens sent to unknown domains", "No user consent"],
  },
  {
    id: "FLOW_SSH_DISCORD",
    title: "SSH key sent to Discord",
    description:
      "Code reads SSH keys and sends them to Discord webhook. This is a common exfiltration technique.",
    severity: "critical",
    stages: [STAGES["SSH_KEYS"]!, STAGES["DISCORD_WEBHOOK"]!],
    constraints: { maxSpan: 2000 },
  },
  {
    id: "FLOW_CRED_DISCORD",
    title: "Credentials sent to Discord",
    description: "Code reads credentials and sends them to Discord webhook for exfiltration.",
    severity: "critical",
    stages: [STAGES["CREDENTIALS"]!, STAGES["DISCORD_WEBHOOK"]!],
    constraints: { maxSpan: 2000 },
  },
  {
    id: "FLOW_SSH_EXEC",
    title: "SSH key used in command execution",
    description: "SSH key content is passed to command execution, potentially for remote access.",
    severity: "high",
    stages: [STAGES["SSH_KEYS"]!, STAGES["CHILD_PROCESS"]!],
    constraints: { maxSpan: 2000 },
    legitimateUses: ["SSH key management tools", "Git operations"],
    redFlags: ["Key content passed to exec", "Unknown remote commands"],
  },

  // Behavioral-style rules (N-stage attack chains)
  {
    id: "BEHAVIOR_CREDENTIAL_EXFIL",
    title: "Credential exfiltration pattern",
    description:
      "Code reads sensitive files, encodes the content, and sends it to an external server. This is the classic credential theft attack chain.",
    severity: "critical",
    stages: [STAGES["FILE_READ"]!, STAGES["ENCODE"]!, STAGES["NETWORK"]!],
    constraints: { maxSpan: 3000 },
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
    stages: [STAGES["NETWORK"]!, STAGES["EXEC"]!],
    constraints: { maxSpan: 1500 },
    redFlags: ["Socket piped to shell", "Remote command execution"],
  },
  {
    id: "BEHAVIOR_SUPPLY_CHAIN_ATTACK",
    title: "Install script attack pattern",
    description:
      "Package lifecycle script accesses environment, executes commands, and phones home. This is a supply chain attack pattern.",
    severity: "high",
    stages: [STAGES["ENV_ACCESS"]!, STAGES["EXEC"]!, STAGES["NETWORK"]!],
    constraints: { minStages: 3, maxSpan: 1000 },
    legitimateUses: ["Build scripts", "Development tools"],
    redFlags: ["Runs in postinstall", "Collects system info", "Sends to unknown domain"],
  },
  {
    id: "BEHAVIOR_DROPPER",
    title: "Malware dropper pattern",
    description:
      "Code downloads content from remote URL, writes it to file, and executes it. This is a dropper/downloader pattern.",
    severity: "critical",
    stages: [STAGES["DOWNLOAD"]!, STAGES["FILE_WRITE"]!, STAGES["EXEC"]!],
    constraints: { maxSpan: 2000 },
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
    stages: [STAGES["CLIPBOARD"]!, STAGES["PERSISTENCE"]!, STAGES["DISCORD_WEBHOOK"]!],
    constraints: { minStages: 2, maxSpan: 3000 },
    legitimateUses: ["Keyboard shortcut extensions"],
    redFlags: ["Captures all keystrokes", "Sends to Discord webhook", "No user consent mechanism"],
  },
  {
    id: "BEHAVIOR_CRYPTO_STEALER",
    title: "Cryptocurrency stealer pattern",
    description: "Code scans for wallet files, extracts keys/seeds, and exfiltrates them.",
    severity: "critical",
    stages: [STAGES["CRYPTO_WALLETS"]!, STAGES["ENCODE"]!, STAGES["DISCORD_WEBHOOK"]!],
    constraints: { minStages: 3, maxSpan: 1500 },
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
    stages: [STAGES["STARTUP_FILE"]!, STAGES["FILE_WRITE"]!],
    constraints: { maxSpan: 2000 },
    legitimateUses: ["Shell configuration tools", "Development environment setup"],
    redFlags: ["Writes to startup files", "Adds hidden entries", "No user interaction"],
  },
  {
    id: "BEHAVIOR_SELF_PROPAGATION",
    title: "Self-propagation pattern",
    description:
      "Code accesses package publishing credentials and attempts to publish itself. This is worm-like behavior.",
    severity: "critical",
    stages: [STAGES["PUBLISH_CREDS"]!, STAGES["PUBLISH_CMD"]!],
    constraints: { maxSpan: 2000 },
    redFlags: ["Accesses publish tokens", "Runs publish commands", "GlassWorm-style worm"],
  },
];

// =============================================================================
// Core Detection Logic
// =============================================================================

/**
 * Find all matches for a set of patterns in content.
 */
function findMatches(content: string, patterns: RegExp[]): { index: number; matched: string }[] {
  const matches: { index: number; matched: string }[] = [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      matches.push({
        index: match.index,
        matched: match[0].slice(0, 80),
      });
    }
  }

  return matches;
}

/**
 * Check if a chain rule matches in the content.
 * Returns array of stage matches if rule triggers, null otherwise.
 */
function checkRule(content: string, rule: ChainRule): StageMatch[] | null {
  const stageMatches: StageMatch[] = [];
  const minStages = rule.constraints.minStages ?? rule.stages.length;
  const maxSpan = rule.constraints.maxSpan ?? 3000;

  // Find matches for each stage
  for (const stage of rule.stages) {
    const matches = findMatches(content, stage.patterns);
    if (matches.length > 0) {
      const firstMatch = matches[0];
      if (firstMatch) {
        stageMatches.push({
          stageId: stage.id,
          stageName: stage.name,
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

// =============================================================================
// Main Export
// =============================================================================

export function checkChains(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = buffer.toString("utf8");

    for (const rule of CHAIN_RULES) {
      const stageMatches = checkRule(content, rule);
      if (!stageMatches) continue;

      // Deduplicate
      const key = `${rule.id}:${filename}`;
      if (seenFindings.has(key)) continue;
      seenFindings.add(key);

      const firstMatch = stageMatches[0];
      if (!firstMatch) continue;

      // Determine category based on rule ID prefix
      const category = rule.id.startsWith("FLOW_") ? "dataflow" : "behavioral";

      findings.push({
        id: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        category,
        location: {
          file: filename,
          line: findLineNumberByIndex(content, firstMatch.index),
        },
        metadata: {
          stagesMatched: stageMatches.length,
          totalStages: rule.stages.length,
          stages: stageMatches.map((m) => ({
            id: m.stageId,
            name: m.stageName,
            matched: m.matched,
            line: findLineNumberByIndex(content, m.index),
          })),
          ...(rule.legitimateUses && { legitimateUses: rule.legitimateUses }),
          ...(rule.redFlags && { redFlags: rule.redFlags }),
        },
      });
    }
  }

  return findings;
}

// Export for testing
export { CHAIN_RULES, STAGES };
