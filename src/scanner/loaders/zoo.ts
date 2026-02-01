import { access, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { BlocklistEntry, ZooData } from "../types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Find the zoo directory, checking multiple locations.
 * Priority:
 * 1. VSIX_AUDIT_ZOO_PATH environment variable
 * 2. Development: ../../.. relative to module (src/scanner/loaders -> zoo)
 * 3. Installed: ../.. relative to dist (dist/scanner/loaders -> zoo)
 */
async function findZooRoot(): Promise<string> {
  // Check environment variable first
  const envPath = process.env["VSIX_AUDIT_ZOO_PATH"];
  if (envPath) {
    return envPath;
  }

  // Development path: src/scanner/loaders -> zoo
  const devPath = join(__dirname, "..", "..", "..", "zoo");
  try {
    await access(devPath);
    return devPath;
  } catch {
    // Not found, try installed path
  }

  // Installed path: dist/scanner/loaders -> zoo
  const installedPath = join(__dirname, "..", "..", "zoo");
  try {
    await access(installedPath);
    return installedPath;
  } catch {
    // Fall back to dev path (will error with helpful message later)
    return devPath;
  }
}

interface BlocklistFile {
  extensions: BlocklistEntry[];
}

function defangDomain(domain: string): string {
  return domain.replace(/\[\.\]/g, ".");
}

/**
 * Generic IOC file parser.
 * @param content - Raw file content
 * @param extractor - Function to extract and validate a value from each line's first field
 * @returns Set of extracted values
 */
function parseIOCFile(content: string, extractor: (field: string) => string | null): Set<string> {
  const result = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const field = trimmed.split(/\s+/)[0];
    if (field) {
      const value = extractor(field);
      if (value) {
        result.add(value);
      }
    }
  }

  return result;
}

/**
 * Parse wallet file format: CURRENCY ADDRESS  # comment
 * Extracts the wallet address (second field) from each line.
 */
function parseWalletFile(content: string): Set<string> {
  const result = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Format: CURRENCY ADDRESS  # comment
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      const address = parts[1];
      if (address && !address.startsWith("#")) {
        result.add(address);
      }
    }
  }

  return result;
}

let cachedZooData: ZooData | undefined;

export async function loadZooData(): Promise<ZooData> {
  if (cachedZooData) {
    return cachedZooData;
  }

  const zooRoot = await findZooRoot();

  const [
    blocklistContent,
    hashesContent,
    domainsContent,
    ipsContent,
    npmContent,
    walletsContent,
    blockchainContent,
  ] = await Promise.all([
    readFile(join(zooRoot, "blocklist", "extensions.json"), "utf8"),
    readFile(join(zooRoot, "iocs", "hashes.txt"), "utf8"),
    readFile(join(zooRoot, "iocs", "c2-domains.txt"), "utf8"),
    readFile(join(zooRoot, "iocs", "c2-ips.txt"), "utf8"),
    readFile(join(zooRoot, "iocs", "malicious-npm.txt"), "utf8"),
    readFile(join(zooRoot, "iocs", "wallets.txt"), "utf8"),
    readFile(join(zooRoot, "iocs", "blockchain-extensions.txt"), "utf8"),
  ]);

  const blocklistFile = JSON.parse(blocklistContent) as BlocklistFile;

  cachedZooData = {
    blocklist: blocklistFile.extensions,
    hashes: parseIOCFile(hashesContent, (hash) =>
      /^[a-f0-9]{64}$/i.test(hash) ? hash.toLowerCase() : null,
    ),
    domains: parseIOCFile(domainsContent, (domain) => defangDomain(domain).toLowerCase()),
    ips: parseIOCFile(ipsContent, (ipWithPort) => ipWithPort.split(":")[0] ?? null),
    maliciousNpmPackages: parseIOCFile(npmContent, (pkg) => pkg.toLowerCase()),
    wallets: parseWalletFile(walletsContent),
    blockchainAllowlist: parseIOCFile(blockchainContent, (extId) => extId),
  };

  return cachedZooData;
}
