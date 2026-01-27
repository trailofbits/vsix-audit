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

function parseHashesFile(content: string): Set<string> {
  const hashes = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const hash = trimmed.split(/\s+/)[0];
    if (hash && /^[a-f0-9]{64}$/i.test(hash)) {
      hashes.add(hash.toLowerCase());
    }
  }

  return hashes;
}

function parseDomainsFile(content: string): Set<string> {
  const domains = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const domain = trimmed.split(/\s+/)[0];
    if (domain) {
      domains.add(defangDomain(domain).toLowerCase());
    }
  }

  return domains;
}

function parseIpsFile(content: string): Set<string> {
  const ips = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const ipWithPort = trimmed.split(/\s+/)[0];
    if (ipWithPort) {
      const ip = ipWithPort.split(":")[0];
      if (ip) {
        ips.add(ip);
      }
    }
  }

  return ips;
}

function parsePackagesFile(content: string): Set<string> {
  const packages = new Set<string>();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const pkg = trimmed.split(/\s+/)[0];
    if (pkg) {
      packages.add(pkg.toLowerCase());
    }
  }

  return packages;
}

let cachedZooData: ZooData | undefined;

export async function loadZooData(): Promise<ZooData> {
  if (cachedZooData) {
    return cachedZooData;
  }

  const [blocklistContent, hashesContent, domainsContent, ipsContent, npmContent] = await Promise.all([
    readFile(join(ZOO_ROOT, "blocklist", "extensions.json"), "utf8"),
    readFile(join(ZOO_ROOT, "iocs", "hashes.txt"), "utf8"),
    readFile(join(ZOO_ROOT, "iocs", "c2-domains.txt"), "utf8"),
    readFile(join(ZOO_ROOT, "iocs", "c2-ips.txt"), "utf8"),
    readFile(join(ZOO_ROOT, "iocs", "malicious-npm.txt"), "utf8"),
  ]);

  const blocklistFile = JSON.parse(blocklistContent) as BlocklistFile;

  cachedZooData = {
    blocklist: blocklistFile.extensions,
    hashes: parseHashesFile(hashesContent),
    domains: parseDomainsFile(domainsContent),
    ips: parseIpsFile(ipsContent),
    maliciousNpmPackages: parsePackagesFile(npmContent),
  };

  return cachedZooData;
}

export function clearZooCache(): void {
  cachedZooData = undefined;
}
