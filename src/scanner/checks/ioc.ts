import { createHash } from "node:crypto";
import { isScannable, SCANNABLE_EXTENSIONS_IOC } from "../constants.js";
import type { Finding, VsixContents, ZooData } from "../types.js";
import { computeLineStarts, findLineNumberByString, getStringContent } from "../utils.js";
import { computeSha256 } from "../vsix.js";

const MAX_DOMAIN_LENGTH = 253;
const MAX_DOMAIN_LABEL_LENGTH = 63;

function isDomainChar(charCode: number): boolean {
  return (
    (charCode >= 48 && charCode <= 57) ||
    (charCode >= 65 && charCode <= 90) ||
    (charCode >= 97 && charCode <= 122) ||
    charCode === 45 ||
    charCode === 46
  );
}

function isAlphaNumeric(charCode: number): boolean {
  return (
    (charCode >= 48 && charCode <= 57) ||
    (charCode >= 65 && charCode <= 90) ||
    (charCode >= 97 && charCode <= 122)
  );
}

function trimDomainCandidate(candidate: string): string {
  let start = 0;
  let end = candidate.length;

  while (start < end && !isAlphaNumeric(candidate.charCodeAt(start))) {
    start++;
  }
  while (end > start && !isAlphaNumeric(candidate.charCodeAt(end - 1))) {
    end--;
  }

  return candidate.slice(start, end);
}

function isValidDomainCandidate(candidate: string): boolean {
  if (candidate.length === 0 || candidate.length > MAX_DOMAIN_LENGTH || !candidate.includes(".")) {
    return false;
  }

  const labels = candidate.split(".");
  if (labels.length < 2) {
    return false;
  }

  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_DOMAIN_LABEL_LENGTH) {
      return false;
    }
    if (
      !isAlphaNumeric(label.charCodeAt(0)) ||
      !isAlphaNumeric(label.charCodeAt(label.length - 1))
    ) {
      return false;
    }
  }

  return true;
}

function extractDomains(content: string): string[] {
  const matches: string[] = [];
  let cursor = 0;

  while (cursor < content.length) {
    while (cursor < content.length && !isDomainChar(content.charCodeAt(cursor))) {
      cursor++;
    }

    const start = cursor;
    let hasDot = false;
    while (cursor < content.length && isDomainChar(content.charCodeAt(cursor))) {
      if (content.charCodeAt(cursor) === 46) {
        hasDot = true;
      }
      cursor++;
    }

    if (!hasDot) {
      continue;
    }

    const candidate = trimDomainCandidate(content.slice(start, cursor)).toLowerCase();
    if (isValidDomainCandidate(candidate)) {
      matches.push(candidate);
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
  if (knownHashes.size === 0) return [];

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
  if (knownDomains.size === 0) return [];

  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = getStringContent(contents, filename, buffer);
    const foundDomains = extractDomains(content);
    let lineStarts: number[] | undefined;

    for (const domain of foundDomains) {
      if (knownDomains.has(domain)) {
        lineStarts ??= computeLineStarts(content);
        const line = findLineNumberByString(content, domain, lineStarts);
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
  if (knownIps.size === 0) return [];

  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = getStringContent(contents, filename, buffer);
    const foundIps = extractIps(content);
    let lineStarts: number[] | undefined;

    for (const ip of foundIps) {
      if (knownIps.has(ip)) {
        lineStarts ??= computeLineStarts(content);
        const line = findLineNumberByString(content, ip, lineStarts);
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

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map<string, number>(
  [...BASE58_ALPHABET].map((c, i): [string, number] => [c, i]),
);

function base58Decode(s: string): Uint8Array | null {
  if (s.length === 0) return null;

  let leadingOnes = 0;
  for (const c of s) {
    if (c === "1") leadingOnes++;
    else break;
  }

  let num = 0n;
  for (const c of s) {
    const idx = BASE58_INDEX.get(c);
    if (idx === undefined) return null;
    num = num * 58n + BigInt(idx);
  }

  // Accumulate bytes LSB-first to keep the loop linear; reverse on write.
  const lsbBytes: number[] = [];
  while (num > 0n) {
    lsbBytes.push(Number(num & 0xffn));
    num >>= 8n;
  }

  const result = new Uint8Array(leadingOnes + lsbBytes.length);
  for (let i = 0; i < lsbBytes.length; i++) {
    result[leadingOnes + lsbBytes.length - 1 - i] = lsbBytes[i]!;
  }
  return result;
}

/**
 * Validates a Bitcoin P2PKH/P2SH address by checking its Base58Check checksum
 * and mainnet version byte. Real addresses encode a 21-byte payload
 * (version + 20-byte hash) followed by the first 4 bytes of
 * SHA256(SHA256(payload)). Random Base58 substrings that happen to match the
 * regex will fail this check.
 */
export function isValidBitcoinAddress(address: string): boolean {
  // Legacy P2PKH/P2SH addresses encode to exactly 25 bytes, which in Base58
  // is 26–35 chars. Skip BigInt math for anything outside that range.
  if (address.length < 26 || address.length > 35) return false;

  const decoded = base58Decode(address);
  if (decoded === null || decoded.length !== 25) return false;

  // Mainnet version byte: 0x00 = P2PKH ("1…"), 0x05 = P2SH ("3…").
  const version = decoded[0];
  if (version !== 0x00 && version !== 0x05) return false;

  const payload = decoded.subarray(0, 21);
  const checksum = decoded.subarray(21, 25);
  const hash1 = createHash("sha256").update(payload).digest();
  const hash2 = createHash("sha256").update(hash1).digest();

  for (let i = 0; i < 4; i++) {
    if (hash2[i] !== checksum[i]) return false;
  }
  return true;
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
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

  // Real Ed25519 keys in Base58 span a wide character set; repeating
  // base64 garbage (e.g., "Li4uLi4u…", "4oCU4oCU…") uses 4–8 unique chars.
  const uniqueChars = new Set(candidate).size;
  if (uniqueChars < 16) return false;

  // Random Base58 keys cluster around ~5.6 bits/char; English-like
  // camelCase identifiers fall under ~4.5; repeating patterns under ~3.
  if (shannonEntropy(candidate) < 4.5) return false;

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

    const content = getStringContent(contents, filename, buffer);
    const lineStarts = computeLineStarts(content);
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

        // For BTC P2PKH/P2SH, verify the Base58Check checksum. The Bech32
        // variant ("bc1…", case-insensitive per BIP173) uses a different
        // checksum scheme and is not validated here.
        if (
          name === "BTC" &&
          wallet.slice(0, 3).toLowerCase() !== "bc1" &&
          !isValidBitcoinAddress(wallet)
        ) {
          continue;
        }

        const line = findLineNumberByString(content, wallet, lineStarts);
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

export function checkGithubC2(contents: VsixContents, githubC2Accounts: Set<string>): Finding[] {
  if (githubC2Accounts.size === 0) return [];

  const findings: Finding[] = [];

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_IOC)) continue;

    const content = getStringContent(contents, filename, buffer);
    const lineStarts = computeLineStarts(content);

    for (const account of githubC2Accounts) {
      // Match GitHub API URLs or raw content URLs containing the username
      const patterns = [
        `api.github.com/repos/${account}/`,
        `raw.githubusercontent.com/${account}/`,
        `github.com/${account}/`,
      ];
      for (const pattern of patterns) {
        const idx = content.indexOf(pattern);
        if (idx === -1) continue;

        const line = findLineNumberByString(content, pattern, lineStarts);
        findings.push({
          id: "KNOWN_GITHUB_C2",
          title: "Known GitHub C2 account reference",
          description:
            `File "${filename}" references GitHub account ` +
            `"${account}" which is associated with malware C2. ` +
            "Malware uses GitHub repos to poll for commands.",
          severity: "critical",
          category: "ioc",
          location: line !== undefined ? { file: filename, line } : { file: filename },
          metadata: {
            account,
            matched: pattern,
          },
        });
        break; // One finding per account per file
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
    ...checkGithubC2(contents, zooData.githubC2Accounts),
  ];
}
