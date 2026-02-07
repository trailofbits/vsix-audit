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

  if (
    ip.startsWith("0.") ||
    ip.startsWith("10.") ||
    ip.startsWith("127.") ||
    ip.startsWith("169.254.") ||
    ip.startsWith("192.168.") ||
    ip === "255.255.255.255" ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^(22[4-9]|2[3-5]\d)\./.test(ip)
  ) {
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

// Wallet patterns ordered from most specific to least specific.
// More specific patterns (BTC, ETH, XMR) are checked first to avoid
// the broad Solana Base58 pattern from matching them.
const WALLET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // Bitcoin Legacy (P2PKH) - starts with 1
  { name: "BTC", pattern: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g },
  // Bitcoin SegWit (P2SH) - starts with 3
  { name: "BTC", pattern: /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g },
  // Bitcoin Bech32 (Native SegWit) - starts with bc1
  { name: "BTC", pattern: /\bbc1[a-z0-9]{39,59}\b/g },
  // Ethereum - 0x + 40 hex chars
  { name: "ETH", pattern: /\b0x[a-fA-F0-9]{40}\b/g },
  // Monero - starts with 4 or 8, 95 chars
  { name: "XMR", pattern: /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g },
  // Solana - Base58, 32-44 chars (common range for pubkeys)
  // This is a broad pattern - checked last to avoid matching BTC addresses
  // Post-match validation is done via isLikelySolanaAddress()
  { name: "SOL", pattern: /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g },
];

/**
 * Validates whether a Base58 string is likely a real Solana address.
 *
 * Filters out:
 * - JS identifiers without digits or only trailing digits
 * - Git/SHA hashes (lowercase hex strings)
 * - Identifiers with clustered numbers (like "Sha256Thumbprint")
 *
 * Real SOL addresses have:
 * - Digits (1-9) distributed throughout
 * - Uppercase letters mixed in (not pure lowercase hex)
 */
export function isLikelySolanaAddress(candidate: string): boolean {
  // Reject pure lowercase hex strings (git hashes, checksums)
  // These match Base58 charset but are clearly not wallets
  if (/^[a-f0-9]+$/.test(candidate)) {
    return false;
  }

  // Must have at least 2 digits
  const digits = candidate.match(/[1-9]/g) ?? [];
  if (digits.length < 2) return false;

  // At least one digit must be in the first 75% of the string
  // This filters out JS identifiers with only trailing numbers like "Type2"
  const firstDigitIndex = candidate.search(/[1-9]/);
  if (firstDigitIndex >= candidate.length * 0.75) return false;

  // Require at least one uppercase letter
  // This filters out pure lowercase identifiers and hex strings
  // Real Base58 addresses use full alphanumeric range
  if (!/[A-HJ-NP-Z]/.test(candidate)) {
    return false;
  }

  return true;
}

export function checkWallets(
  contents: VsixContents,
  knownWallets: Set<string>,
  blockchainAllowlist?: Set<string>,
): Finding[] {
  // Skip wallet detection for allowlisted blockchain development extensions
  const extensionId = `${contents.manifest.publisher}.${contents.manifest.name}`;
  if (blockchainAllowlist?.has(extensionId)) {
    return [];
  }

  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = buffer.toString("utf8");
    // Track wallets already found in this file to avoid duplicate findings
    // (e.g., BTC addresses matching both BTC and SOL patterns)
    const seenWallets = new Set<string>();

    for (const { name, pattern } of WALLET_PATTERNS) {
      // Reset regex state
      pattern.lastIndex = 0;

      for (const match of content.matchAll(pattern)) {
        const wallet = match[0];

        // Skip if we've already reported this wallet address
        if (seenWallets.has(wallet)) continue;
        seenWallets.add(wallet);

        // For SOL pattern, apply additional validation to filter out JS identifiers
        if (name === "SOL" && !isLikelySolanaAddress(wallet)) {
          continue;
        }

        const line = findLineNumberByString(content, wallet);
        const isKnownMalicious = knownWallets.has(wallet);

        if (isKnownMalicious) {
          findings.push({
            id: "KNOWN_MALWARE_WALLET",
            title: "Known malware wallet address detected",
            description:
              `File "${filename}" contains known malicious ${name} wallet: ${wallet}. ` +
              "This wallet is associated with malware campaigns.",
            severity: "critical",
            category: "ioc",
            location: line !== undefined ? { file: filename, line } : { file: filename },
            metadata: { wallet, currency: name, knownMalicious: true },
          });
        } else {
          findings.push({
            id: "CRYPTO_WALLET_DETECTED",
            title: "Cryptocurrency wallet address detected",
            description:
              `File "${filename}" contains ${name} wallet address: ${wallet}. ` +
              "VS Code extensions should not contain wallet addresses.",
            severity: "high",
            category: "ioc",
            location: line !== undefined ? { file: filename, line } : { file: filename },
            metadata: { wallet, currency: name, knownMalicious: false },
          });
        }
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
    ...checkWallets(contents, zooData.wallets, zooData.blockchainAllowlist),
  ];
}
