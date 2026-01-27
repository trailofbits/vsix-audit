import type { BlocklistEntry, Finding, VsixManifest } from "../types.js";

function matchesWildcard(extensionId: string, pattern: string): boolean {
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return extensionId.startsWith(prefix + ".");
  }
  return extensionId === pattern;
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
