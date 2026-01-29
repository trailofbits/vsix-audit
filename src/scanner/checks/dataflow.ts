import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import { findLineNumberByIndex } from "../utils.js";

/**
 * Data flow analysis detects when sensitive data (sources) flows to
 * dangerous operations (sinks). This catches credential exfiltration
 * regardless of string obfuscation.
 */

interface DataSource {
  id: string;
  name: string;
  description: string;
  patterns: RegExp[];
  apis: RegExp[];
}

interface DataSink {
  id: string;
  name: string;
  description: string;
  patterns: RegExp[];
}

interface DataFlowRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  source: string;
  sink: string;
  legitimateUses?: string[];
  redFlags?: string[];
}

interface DataFlowMatch {
  sourceMatch: { index: number; matched: string };
  sinkMatch: { index: number; matched: string };
  distance: number;
}

// Sources: Where sensitive data originates
const SOURCES: DataSource[] = [
  {
    id: "SSH_KEYS",
    name: "SSH private keys",
    description: "SSH private key files",
    patterns: [
      /\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)/gi,
      /\.ssh\/config/gi,
      /BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/gi,
      /BEGIN\s+OPENSSH\s+PRIVATE\s+KEY/gi,
    ],
    apis: [
      /(?:fs|promises?)\.readFile(?:Sync)?\s*\([^)]*\.ssh/gi,
      /readFile(?:Sync)?\s*\([^)]*id_(?:rsa|ed25519)/gi,
    ],
  },
  {
    id: "CRYPTO_WALLETS",
    name: "Cryptocurrency wallets",
    description: "Wallet files and seed phrases",
    patterns: [
      /\.ethereum/gi,
      /\.bitcoin/gi,
      /wallet\.dat/gi,
      /keystore\/[a-z0-9-]+/gi,
      /solana\/id\.json/gi,
      /Exodus/gi,
      /MetaMask/gi,
      /phantom/gi,
    ],
    apis: [
      /readFile(?:Sync)?\s*\([^)]*(?:wallet|ethereum|bitcoin|keystore)/gi,
      /readFile(?:Sync)?\s*\([^)]*\.solana/gi,
    ],
  },
  {
    id: "CREDENTIALS",
    name: "Credential files",
    description: "Environment files and credential stores",
    patterns: [
      /\.env(?:\.local|\.production)?/gi,
      /\.npmrc/gi,
      /\.netrc/gi,
      /\.git-credentials/gi,
      /credentials\.json/gi,
      /secrets?\./gi,
    ],
    apis: [
      /readFile(?:Sync)?\s*\([^)]*\.env/gi,
      /readFile(?:Sync)?\s*\([^)]*\.npmrc/gi,
      /process\.env\.[A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/gi,
    ],
  },
  {
    id: "BROWSER_DATA",
    name: "Browser stored data",
    description: "Browser cookies, passwords, and local storage",
    patterns: [
      /Google[/\\]Chrome[/\\].*Login\s+Data/gi,
      /Google[/\\]Chrome[/\\].*Cookies/gi,
      /Mozilla[/\\]Firefox[/\\].*logins\.json/gi,
      /BraveSoftware[/\\].*Login\s+Data/gi,
      /Microsoft[/\\]Edge[/\\].*Login\s+Data/gi,
      /Local\s+Storage[/\\]leveldb/gi,
    ],
    apis: [
      /readFile(?:Sync)?\s*\([^)]*(?:Chrome|Firefox|Edge|Brave)/gi,
      /readFile(?:Sync)?\s*\([^)]*Login\s*Data/gi,
    ],
  },
  {
    id: "API_TOKENS",
    name: "API tokens and keys",
    description: "API keys and authentication tokens",
    patterns: [
      /(?:GITHUB|GITLAB|BITBUCKET)_(?:TOKEN|API_KEY)/gi,
      /NPM_TOKEN/gi,
      /OPENVSX_(?:TOKEN|PAT)/gi,
      /(?:AWS|AZURE|GCP)_(?:ACCESS_KEY|SECRET|TOKEN)/gi,
      /OPENAI_API_KEY/gi,
      /ANTHROPIC_API_KEY/gi,
    ],
    apis: [/process\.env\.(?:GITHUB|GITLAB|NPM|AWS|AZURE|OPENAI|ANTHROPIC)/gi],
  },
];

// Sinks: Where data leaves the system
const SINKS: DataSink[] = [
  {
    id: "NETWORK_SEND",
    name: "Network transmission",
    description: "HTTP requests that send data externally",
    patterns: [
      /fetch\s*\([^)]*,\s*\{[^}]*method\s*:\s*['"](?:POST|PUT)/gi,
      /axios\.(?:post|put)\s*\(/gi,
      /https?\.request\s*\([^)]*method\s*:\s*['"](?:POST|PUT)/gi,
      /request\.(?:post|put)\s*\(/gi,
      /got\.(?:post|put)\s*\(/gi,
      /superagent\.(?:post|put)\s*\(/gi,
    ],
  },
  {
    id: "WEBSOCKET_SEND",
    name: "WebSocket transmission",
    description: "Data sent over WebSocket connections",
    patterns: [/\.send\s*\([^)]+\)/gi, /WebSocket\s*\([^)]*\)/gi, /ws\.send\s*\(/gi],
  },
  {
    id: "DISCORD_WEBHOOK",
    name: "Discord webhook",
    description: "Discord webhook exfiltration",
    patterns: [/discord\.com\/api\/webhooks/gi, /discordapp\.com\/api\/webhooks/gi],
  },
  {
    id: "EVAL_EXEC",
    name: "Code execution",
    description: "eval or Function constructor",
    patterns: [
      /\beval\s*\(/gi,
      /new\s+Function\s*\(/gi,
      /\(\s*\)\s*\[\s*['"]constructor['"]\s*\]/gi,
    ],
  },
  {
    id: "CHILD_PROCESS",
    name: "Shell execution",
    description: "Command execution via child_process",
    patterns: [
      /child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/gi,
      /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*\$\{/gi,
    ],
  },
];

// Critical data flow combinations
const FLOW_RULES: DataFlowRule[] = [
  {
    id: "FLOW_SSH_KEY_EXFIL",
    title: "SSH key exfiltration pattern",
    description:
      "Code reads SSH private keys and sends data over network. This is a credential theft pattern.",
    severity: "critical",
    source: "SSH_KEYS",
    sink: "NETWORK_SEND",
    redFlags: ["Reads .ssh directory", "Sends to external URL"],
  },
  {
    id: "FLOW_WALLET_EXFIL",
    title: "Cryptocurrency wallet exfiltration",
    description:
      "Code accesses cryptocurrency wallet data and sends it over network. This is a crypto theft pattern.",
    severity: "critical",
    source: "CRYPTO_WALLETS",
    sink: "NETWORK_SEND",
    redFlags: ["Accesses wallet files", "Sends to external server"],
  },
  {
    id: "FLOW_CRED_EXFIL",
    title: "Credential exfiltration pattern",
    description: "Code reads credential files (.env, .npmrc, etc.) and sends data over network.",
    severity: "critical",
    source: "CREDENTIALS",
    sink: "NETWORK_SEND",
    redFlags: ["Reads environment files", "HTTP POST to external"],
  },
  {
    id: "FLOW_BROWSER_EXFIL",
    title: "Browser data exfiltration",
    description: "Code accesses browser stored passwords/cookies and sends them over network.",
    severity: "critical",
    source: "BROWSER_DATA",
    sink: "NETWORK_SEND",
    redFlags: ["Reads Chrome/Firefox data", "Network exfiltration"],
  },
  {
    id: "FLOW_TOKEN_EXFIL",
    title: "API token exfiltration",
    description: "Code accesses API tokens from environment and sends them to external server.",
    severity: "critical",
    source: "API_TOKENS",
    sink: "NETWORK_SEND",
    legitimateUses: ["Token validation services", "OAuth flows"],
    redFlags: ["Tokens sent to unknown domains", "No user consent"],
  },
  {
    id: "FLOW_SSH_DISCORD",
    title: "SSH key sent to Discord",
    description:
      "Code reads SSH keys and sends them to Discord webhook. This is a common exfiltration technique.",
    severity: "critical",
    source: "SSH_KEYS",
    sink: "DISCORD_WEBHOOK",
  },
  {
    id: "FLOW_CRED_DISCORD",
    title: "Credentials sent to Discord",
    description: "Code reads credentials and sends them to Discord webhook for exfiltration.",
    severity: "critical",
    source: "CREDENTIALS",
    sink: "DISCORD_WEBHOOK",
  },
  {
    id: "FLOW_SSH_EXEC",
    title: "SSH key used in command execution",
    description: "SSH key content is passed to command execution, potentially for remote access.",
    severity: "high",
    source: "SSH_KEYS",
    sink: "CHILD_PROCESS",
    legitimateUses: ["SSH key management tools", "Git operations"],
    redFlags: ["Key content passed to exec", "Unknown remote commands"],
  },
];

/**
 * Find all matches for a set of patterns
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
 * Check if source and sink are in proximity (within same function/block)
 * Uses a simple heuristic: within 2000 characters of each other
 */
function areInProximity(sourceIndex: number, sinkIndex: number, maxDistance = 2000): boolean {
  return Math.abs(sourceIndex - sinkIndex) < maxDistance;
}

export function checkDataFlow(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = buffer.toString("utf8");

    // Find all source and sink matches
    const sourceMatches = new Map<string, { index: number; matched: string }[]>();
    const sinkMatches = new Map<string, { index: number; matched: string }[]>();

    for (const source of SOURCES) {
      const matches = [
        ...findMatches(content, source.patterns),
        ...findMatches(content, source.apis),
      ];
      if (matches.length > 0) {
        sourceMatches.set(source.id, matches);
      }
    }

    for (const sink of SINKS) {
      const matches = findMatches(content, sink.patterns);
      if (matches.length > 0) {
        sinkMatches.set(sink.id, matches);
      }
    }

    // Check each flow rule
    for (const rule of FLOW_RULES) {
      const sources = sourceMatches.get(rule.source);
      const sinks = sinkMatches.get(rule.sink);

      if (!sources || !sinks) continue;

      // Find the closest source-sink pair
      let closestPair: DataFlowMatch | null = null;

      for (const sourceMatch of sources) {
        for (const sinkMatch of sinks) {
          if (areInProximity(sourceMatch.index, sinkMatch.index)) {
            const distance = Math.abs(sourceMatch.index - sinkMatch.index);
            if (!closestPair || distance < closestPair.distance) {
              closestPair = { sourceMatch, sinkMatch, distance };
            }
          }
        }
      }

      if (!closestPair) continue;

      // Deduplicate
      const key = `${rule.id}:${filename}`;
      if (seenFindings.has(key)) continue;
      seenFindings.add(key);

      const source = SOURCES.find((s) => s.id === rule.source);
      const sink = SINKS.find((s) => s.id === rule.sink);

      findings.push({
        id: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        category: "dataflow",
        location: {
          file: filename,
          line: findLineNumberByIndex(content, closestPair.sourceMatch.index),
        },
        metadata: {
          source: {
            type: source?.name ?? rule.source,
            matched: closestPair.sourceMatch.matched,
          },
          sink: {
            type: sink?.name ?? rule.sink,
            matched: closestPair.sinkMatch.matched,
            line: findLineNumberByIndex(content, closestPair.sinkMatch.index),
          },
          distance: closestPair.distance,
          ...(rule.legitimateUses && { legitimateUses: rule.legitimateUses }),
          ...(rule.redFlags && { redFlags: rule.redFlags }),
        },
      });
    }
  }

  return findings;
}
