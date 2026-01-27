import { isScannable, SCANNABLE_EXTENSIONS_IOC } from "../constants.js";
import type { Finding, VsixContents, ZooData } from "../types.js";
import { findLineNumberByString } from "../utils.js";
import { computeSha256 } from "../vsix.js";

function extractDomains(content: string): string[] {
  const domainPattern =
    /(?:https?:\/\/)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)/g;
  const matches: string[] = [];

  for (const match of content.matchAll(domainPattern)) {
    const domain = match[1];
    if (domain) {
      matches.push(domain.toLowerCase());
    }
  }

  return matches;
}

function extractIps(content: string): string[] {
  const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const matches: string[] = [];

  for (const match of content.matchAll(ipPattern)) {
    const ip = match[1];
    if (ip && isValidIp(ip)) {
      matches.push(ip);
    }
  }

  return matches;
}

function isValidIp(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return false;
  }

  if (ip === "0.0.0.0" || ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.")) {
    return false;
  }

  return true;
}

export function checkHashes(contents: VsixContents, knownHashes: Set<string>): Finding[] {
  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    const hash = computeSha256(buffer);

    if (knownHashes.has(hash)) {
      findings.push({
        id: "KNOWN_MALWARE_HASH",
        title: "File matches known malware hash",
        description: `File "${filename}" has SHA256 hash ${hash} which is in the malware database`,
        severity: "critical",
        category: "ioc",
        location: {
          file: filename,
        },
        metadata: {
          sha256: hash,
        },
      });
    }
  }

  return findings;
}

export function checkDomains(contents: VsixContents, knownDomains: Set<string>): Finding[] {
  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = buffer.toString("utf8");
    const foundDomains = extractDomains(content);

    for (const domain of foundDomains) {
      if (knownDomains.has(domain)) {
        const line = findLineNumberByString(content, domain);
        findings.push({
          id: "KNOWN_C2_DOMAIN",
          title: "Known C2 domain detected",
          description: `File "${filename}" contains known C2 domain: ${domain}`,
          severity: "critical",
          category: "ioc",
          location: line !== undefined ? { file: filename, line } : { file: filename },
          metadata: {
            domain,
          },
        });
      }
    }
  }

  return findings;
}

export function checkIps(contents: VsixContents, knownIps: Set<string>): Finding[] {
  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = buffer.toString("utf8");
    const foundIps = extractIps(content);

    for (const ip of foundIps) {
      if (knownIps.has(ip)) {
        const line = findLineNumberByString(content, ip);
        findings.push({
          id: "KNOWN_C2_IP",
          title: "Known C2 IP address detected",
          description: `File "${filename}" contains known C2 IP: ${ip}`,
          severity: "critical",
          category: "ioc",
          location: line !== undefined ? { file: filename, line } : { file: filename },
          metadata: {
            ip,
          },
        });
      }
    }
  }

  return findings;
}

export function checkIocs(contents: VsixContents, zooData: ZooData): Finding[] {
  return [
    ...checkHashes(contents, zooData.hashes),
    ...checkDomains(contents, zooData.domains),
    ...checkIps(contents, zooData.ips),
  ];
}
