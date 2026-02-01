import type { Finding } from "./types.js";

/**
 * Capability extraction from scanner findings.
 *
 * Aggregates findings into high-level capability buckets for quick
 * understanding of what an extension can do.
 */

export interface Evidence {
  file: string;
  line?: number | undefined;
  matched?: string | undefined;
}

export interface CapabilityInfo {
  detected: boolean;
  summary: string[];
  evidence: Evidence[];
}

export interface Capabilities {
  network: CapabilityInfo;
  execution: CapabilityInfo;
  fileAccess: CapabilityInfo;
  credentials: CapabilityInfo;
  obfuscation: CapabilityInfo;
}

// Mapping of finding ID patterns to capabilities
const CAPABILITY_PATTERNS: Record<keyof Capabilities, RegExp[]> = {
  network: [
    /NETWORK/i,
    /DISCORD/i,
    /WEBHOOK/i,
    /HTTP/i,
    /WEBSOCKET/i,
    /FETCH/i,
    /AXIOS/i,
    /SOCKET/i,
    /EXFIL/i,
  ],
  execution: [
    /CHILD_PROCESS/i,
    /EXEC/i,
    /EVAL/i,
    /SPAWN/i,
    /POWERSHELL/i,
    /SHELL/i,
    /CMD/i,
    /DROPPER/i,
    /REVERSE_SHELL/i,
  ],
  fileAccess: [
    /FILE/i,
    /READ/i,
    /WRITE/i,
    /HOME/i,
    /PATH/i,
    /STARTUP/i,
    /PERSISTENCE/i,
    /DROPPER/i,
  ],
  credentials: [
    /SSH/i,
    /CREDENTIAL/i,
    /WALLET/i,
    /BROWSER_DATA/i,
    /TOKEN/i,
    /API_KEY/i,
    /PASSWORD/i,
    /SECRET/i,
    /CRYPTO/i,
    /KEY/i,
    /NPM/i,
    /ENV/i,
  ],
  obfuscation: [
    /OBFUSCATION/i,
    /ENTROPY/i,
    /HEX_/i,
    /EVAL_ATOB/i,
    /BASE64/i,
    /UNICODE/i,
    /INVISIBLE/i,
    /HOMOGLYPH/i,
    /ENCODED/i,
  ],
};

// Summary text generators based on finding IDs
const SUMMARY_GENERATORS: Record<keyof Capabilities, (ids: string[]) => string[]> = {
  network: (ids) => {
    const summaries: string[] = [];
    if (ids.some((id) => /DISCORD|WEBHOOK/i.test(id))) summaries.push("Discord webhooks");
    if (ids.some((id) => /WEBSOCKET/i.test(id))) summaries.push("WebSocket");
    if (ids.some((id) => /NETWORK|HTTP|FETCH|AXIOS/i.test(id))) summaries.push("HTTP client");
    if (ids.some((id) => /SOCKET/i.test(id))) summaries.push("Raw sockets");
    return summaries.length ? summaries : ["Network activity"];
  },
  execution: (ids) => {
    const summaries: string[] = [];
    if (ids.some((id) => /CHILD_PROCESS|SPAWN|EXEC/i.test(id)))
      summaries.push("Shell commands (child_process)");
    if (ids.some((id) => /EVAL/i.test(id))) summaries.push("Dynamic code (eval)");
    if (ids.some((id) => /POWERSHELL/i.test(id))) summaries.push("PowerShell");
    if (ids.some((id) => /REVERSE_SHELL/i.test(id))) summaries.push("Reverse shell pattern");
    if (ids.some((id) => /DROPPER/i.test(id))) summaries.push("Dropper pattern");
    return summaries.length ? summaries : ["Code execution"];
  },
  fileAccess: (ids) => {
    const summaries: string[] = [];
    if (ids.some((id) => /SSH/i.test(id))) summaries.push(".ssh directory");
    if (ids.some((id) => /HOME/i.test(id))) summaries.push("Home directory");
    if (ids.some((id) => /STARTUP|BASHRC|PROFILE/i.test(id))) summaries.push("Startup files");
    if (ids.some((id) => /WRITE|PERSIST/i.test(id))) summaries.push("File writes");
    if (ids.some((id) => /READ/i.test(id))) summaries.push("File reads");
    return summaries.length ? summaries : ["File system access"];
  },
  credentials: (ids) => {
    const summaries: string[] = [];
    if (ids.some((id) => /SSH/i.test(id))) summaries.push("SSH keys");
    if (ids.some((id) => /WALLET|CRYPTO/i.test(id))) summaries.push("Crypto wallets");
    if (ids.some((id) => /BROWSER/i.test(id))) summaries.push("Browser data");
    if (ids.some((id) => /ENV/i.test(id))) summaries.push("Environment variables");
    if (ids.some((id) => /TOKEN|API_KEY/i.test(id))) summaries.push("API tokens");
    if (ids.some((id) => /NPM/i.test(id))) summaries.push("npm credentials");
    if (ids.some((id) => /GIT/i.test(id))) summaries.push("Git credentials");
    return summaries.length ? summaries : ["Sensitive data"];
  },
  obfuscation: (ids) => {
    const summaries: string[] = [];
    if (ids.some((id) => /ENTROPY/i.test(id))) summaries.push("High entropy code");
    if (ids.some((id) => /HEX_|BASE64|ENCODED/i.test(id))) summaries.push("Encoded strings");
    if (ids.some((id) => /UNICODE|INVISIBLE|HOMOGLYPH/i.test(id)))
      summaries.push("Unicode manipulation");
    if (ids.some((id) => /EVAL_ATOB/i.test(id))) summaries.push("eval(atob()) pattern");
    return summaries.length ? summaries : ["Code obfuscation"];
  },
};

/**
 * Determine which capability a finding belongs to based on its ID.
 */
function getCapability(findingId: string): (keyof Capabilities)[] {
  const caps: (keyof Capabilities)[] = [];

  for (const [cap, patterns] of Object.entries(CAPABILITY_PATTERNS)) {
    if (patterns.some((p) => p.test(findingId))) {
      caps.push(cap as keyof Capabilities);
    }
  }

  return caps;
}

/**
 * Extract capabilities from scanner findings.
 */
export function extractCapabilities(findings: Finding[]): Capabilities {
  const capFindings: Record<keyof Capabilities, Finding[]> = {
    network: [],
    execution: [],
    fileAccess: [],
    credentials: [],
    obfuscation: [],
  };

  // Categorize findings by capability
  for (const finding of findings) {
    const caps = getCapability(finding.id);
    for (const cap of caps) {
      capFindings[cap].push(finding);
    }
  }

  // Build capability info for each category
  const capabilities: Capabilities = {
    network: buildCapabilityInfo(capFindings.network, "network"),
    execution: buildCapabilityInfo(capFindings.execution, "execution"),
    fileAccess: buildCapabilityInfo(capFindings.fileAccess, "fileAccess"),
    credentials: buildCapabilityInfo(capFindings.credentials, "credentials"),
    obfuscation: buildCapabilityInfo(capFindings.obfuscation, "obfuscation"),
  };

  return capabilities;
}

function buildCapabilityInfo(findings: Finding[], cap: keyof Capabilities): CapabilityInfo {
  if (findings.length === 0) {
    return { detected: false, summary: [], evidence: [] };
  }

  const ids = [...new Set(findings.map((f) => f.id))];
  const summary = SUMMARY_GENERATORS[cap](ids);

  const evidence: Evidence[] = [];
  for (const f of findings) {
    if (!f.location) continue;
    const ev: Evidence = { file: f.location.file };
    if (f.location.line !== undefined) ev.line = f.location.line;
    const matched = extractMatched(f);
    if (matched) ev.matched = matched;
    evidence.push(ev);
    if (evidence.length >= 10) break;
  }

  return { detected: true, summary, evidence };
}

function extractMatched(finding: Finding): string | undefined {
  const meta = finding.metadata;
  if (!meta) return undefined;

  // Try to extract matched text from various metadata formats
  if (typeof meta["matched"] === "string") return meta["matched"];
  const stages = meta["stages"];
  if (Array.isArray(stages) && stages.length > 0) {
    const stage = stages[0] as { matched?: string };
    if (stage?.matched) return stage.matched;
  }
  const source = meta["source"];
  if (typeof source === "object" && source !== null) {
    const src = source as { matched?: string };
    if (src?.matched) return src.matched;
  }

  return undefined;
}
