import type { Finding, Observation, ScanResult } from "#internal/scanner/types.js";

export interface Evidence {
  file: string;
  line: number;
  column: number;
  matched: string;
}

export interface CapabilityInfo {
  detected: boolean;
  summary: string[];
  evidence: Evidence[];
  /** Detector signals remain available without being promoted into observed API calls. */
  indicators: Finding[];
}

export interface Capabilities {
  network: CapabilityInfo;
  execution: CapabilityInfo;
  fileAccess: CapabilityInfo;
  credentials: CapabilityInfo;
  obfuscation: CapabilityInfo;
}

/** Summarize source observations separately from security-detector indicators. */
export function extractCapabilities(
  result: Pick<ScanResult, "observations" | "findings">,
): Capabilities {
  return {
    network: buildCapabilityInfo(result, "network"),
    execution: buildCapabilityInfo(result, "execution"),
    fileAccess: buildCapabilityInfo(result, "fileAccess"),
    credentials: buildCapabilityInfo(result, "credentials"),
    obfuscation: buildCapabilityInfo(result, "obfuscation"),
  };
}

function evidence(observation: Observation): Evidence {
  return { ...observation.location, matched: observation.snippet };
}

function buildCapabilityInfo(
  result: Pick<ScanResult, "observations" | "findings">,
  capability: keyof Capabilities,
): CapabilityInfo {
  const matching = result.observations.filter((item) => item.capability === capability);
  return {
    detected: matching.length > 0,
    summary: [...new Set(matching.map((item) => `${item.kind}: ${item.api}`))],
    evidence: matching.map(evidence),
    indicators: result.findings.filter((item) => item.capabilities?.includes(capability) === true),
  };
}
