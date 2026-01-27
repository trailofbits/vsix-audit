import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { BlocklistEntry, ZooData } from "../types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ZOO_ROOT = join(__dirname, "..", "..", "..", "zoo");

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

let cachedZooData: ZooData | undefined;

export async function loadZooData(): Promise<ZooData> {
  if (cachedZooData) {
    return cachedZooData;
  }

  const [blocklistContent, hashesContent, domainsContent, ipsContent, npmContent] =
    await Promise.all([
      readFile(join(ZOO_ROOT, "blocklist", "extensions.json"), "utf8"),
      readFile(join(ZOO_ROOT, "iocs", "hashes.txt"), "utf8"),
      readFile(join(ZOO_ROOT, "iocs", "c2-domains.txt"), "utf8"),
      readFile(join(ZOO_ROOT, "iocs", "c2-ips.txt"), "utf8"),
      readFile(join(ZOO_ROOT, "iocs", "malicious-npm.txt"), "utf8"),
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
  };

  return cachedZooData;
}
