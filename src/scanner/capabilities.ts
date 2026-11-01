import type { Finding } from "#internal/scanner/types.js";

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

/** Aggregate detector-declared capabilities without interpreting finding identifiers. */
export function extractCapabilities(findings: Finding[]): Capabilities {
  return {
    network: buildCapabilityInfo(findings, "network"),
    execution: buildCapabilityInfo(findings, "execution"),
    fileAccess: buildCapabilityInfo(findings, "fileAccess"),
    credentials: buildCapabilityInfo(findings, "credentials"),
    obfuscation: buildCapabilityInfo(findings, "obfuscation"),
  };
}

function buildCapabilityInfo(findings: Finding[], capability: keyof Capabilities): CapabilityInfo {
  const matching = findings.filter(
    (finding) => finding.capabilities?.includes(capability) === true,
  );
  const evidence: Evidence[] = [];
  for (const finding of matching) {
    if (finding.location === undefined) continue;
    const matched = finding.metadata?.matched ?? finding.metadata?.["codeSnippet"];
    evidence.push({
      ...finding.location,
      ...(typeof matched === "string" && matched !== "" ? { matched } : {}),
    });
    if (evidence.length === 10) break;
  }
  return {
    detected: matching.length > 0,
    summary: [...new Set(matching.map((finding) => finding.title))],
    evidence,
  };
}
