import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  BlocklistEntry,
  MaliciousNpmVersionAdvisory,
  TelemetryCategory,
  TelemetryServiceInfo,
  ZooData,
} from "#internal/scanner/types.js";

/** Locate bundled detection data, with an explicit override for custom datasets. */
export function getZooRoot(): string {
  const override = process.env["VSIX_AUDIT_ZOO_PATH"];
  return override === undefined || override === ""
    ? join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "zoo")
    : override;
}

interface BlocklistFile {
  extensions: BlocklistEntry[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expectStringField(
  record: Record<string, unknown>,
  field: string,
  context: string,
): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${context}: field "${field}" must be a non-empty string`);
  }
  return value;
}

function expectStringArrayField(
  record: Record<string, unknown>,
  field: string,
  context: string,
): string[] {
  const value = record[field];
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((item): item is string => typeof item === "string" && item.length > 0)
  ) {
    throw new Error(`${context}: field "${field}" must be a non-empty string array`);
  }
  return value;
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
    if (field !== undefined && field !== "") {
      const value = extractor(field);
      if (value !== null && value !== "") {
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
      if (address !== undefined && address !== "" && !address.startsWith("#")) {
        result.add(address);
      }
    }
  }

  return result;
}

/**
 * Parse telemetry services file format: SERVICE_NAME  CATEGORY  DOMAIN1,DOMAIN2,...
 * Returns a map from domain to service info for fast lookup.
 */
function parseTelemetryServices(content: string): Map<string, TelemetryServiceInfo> {
  const result = new Map<string, TelemetryServiceInfo>();
  const validCategories = new Set<TelemetryCategory>(["analytics", "crash-reporting", "apm"]);

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Format: SERVICE_NAME  CATEGORY  DOMAIN1,DOMAIN2,...
    // Use regex to split on 2+ whitespace to handle multi-word service names
    const parts = trimmed.split(/\s{2,}/);
    if (parts.length < 3) continue;

    const name = parts[0];
    const category = parts[1] as TelemetryCategory;
    const domainsStr = parts[2];

    if (
      name === undefined ||
      name === "" ||
      !validCategories.has(category) ||
      domainsStr === undefined ||
      domainsStr === ""
    )
      continue;

    const domains = domainsStr.split(",").map((d) => d.trim().toLowerCase());
    const serviceInfo: TelemetryServiceInfo = { name, category, domains };

    // Map each domain to this service for fast lookup
    for (const domain of domains) {
      if (domain) {
        result.set(domain, serviceInfo);
      }
    }
  }

  return result;
}

function parseVersionAdvisory(
  entry: Record<string, unknown>,
  context: string,
): MaliciousNpmVersionAdvisory {
  const name = expectStringField(entry, "name", context).toLowerCase();
  const affectedVersions = expectStringArrayField(entry, "affectedVersions", context);
  const advisory: MaliciousNpmVersionAdvisory = {
    name,
    affectedVersions,
    advisory: expectStringField(entry, "advisory", context),
    reason: expectStringField(entry, "reason", context),
  };

  const campaign = entry["campaign"];
  if (campaign !== undefined) {
    if (typeof campaign !== "string" || campaign.length === 0) {
      throw new Error(`${context}: field "campaign" must be a non-empty string when present`);
    }
    advisory.campaign = campaign;
  }

  const references = entry["references"];
  if (references !== undefined) {
    if (
      !Array.isArray(references) ||
      !references.every((item): item is string => typeof item === "string" && item.length > 0)
    ) {
      throw new Error(`${context}: field "references" must be a string array when present`);
    }
    advisory.references = references;
  }

  return advisory;
}

function parseMaliciousNpmVersions(content: string): Map<string, MaliciousNpmVersionAdvisory[]> {
  const parsed = JSON.parse(content) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("malicious-npm-versions.json must contain a JSON object");
  }

  const packages = parsed["packages"];
  if (!Array.isArray(packages)) {
    throw new Error('malicious-npm-versions.json field "packages" must be an array');
  }

  const result = new Map<string, MaliciousNpmVersionAdvisory[]>();
  for (const [index, entry] of packages.entries()) {
    const context = `malicious-npm-versions.json packages[${index}]`;
    if (!isRecord(entry)) {
      throw new Error(`${context} must be an object`);
    }

    const advisory = parseVersionAdvisory(entry, context);
    const name = advisory.name;

    const existing = result.get(name) ?? [];
    existing.push(advisory);
    result.set(name, existing);
  }

  return result;
}

let cachedZooData: { root: string; result: Promise<ZooData> } | undefined;

/** Load required threat intelligence once for each selected dataset root. */
export function loadZooData(root = getZooRoot()): Promise<ZooData> {
  if (cachedZooData?.root !== root) {
    const result: Promise<ZooData> = readZooData(root).catch((error: unknown): never => {
      if (cachedZooData?.result === result) cachedZooData = undefined;
      throw error instanceof Error ? error : new Error(String(error), { cause: error });
    });
    cachedZooData = { root, result };
  }
  return cachedZooData.result;
}

async function readDataset(root: string, path: string): Promise<string> {
  const file = join(root, path);
  try {
    return await readFile(file, "utf8");
  } catch (error) {
    throw new Error(
      `Cannot load detection dataset ${file}. Restore the file or fix VSIX_AUDIT_ZOO_PATH.`,
      { cause: error },
    );
  }
}

async function readZooData(zooRoot: string): Promise<ZooData> {
  const [
    blocklistContent,
    hashesContent,
    domainsContent,
    ipsContent,
    npmContent,
    walletsContent,
    blockchainContent,
    telemetryContent,
    githubC2Content,
    npmVersionsContent,
  ] = await Promise.all([
    readDataset(zooRoot, "blocklist/extensions.json"),
    readDataset(zooRoot, "iocs/hashes.txt"),
    readDataset(zooRoot, "iocs/c2-domains.txt"),
    readDataset(zooRoot, "iocs/c2-ips.txt"),
    readDataset(zooRoot, "iocs/malicious-npm.txt"),
    readDataset(zooRoot, "iocs/wallets.txt"),
    readDataset(zooRoot, "iocs/blockchain-extensions.txt"),
    readDataset(zooRoot, "telemetry/known-services.txt"),
    readDataset(zooRoot, "iocs/github-c2.txt"),
    readDataset(zooRoot, "iocs/malicious-npm-versions.json"),
  ]);

  const blocklistFile = JSON.parse(blocklistContent) as BlocklistFile;

  return {
    blocklist: blocklistFile.extensions,
    hashes: parseIOCFile(hashesContent, (hash) =>
      /^[a-f0-9]{64}$/i.test(hash) ? hash.toLowerCase() : null,
    ),
    domains: parseIOCFile(domainsContent, (domain) => defangDomain(domain).toLowerCase()),
    ips: parseIOCFile(ipsContent, (ipWithPort) => ipWithPort.split(":")[0] ?? null),
    maliciousNpmPackages: parseIOCFile(npmContent, (pkg) => pkg.toLowerCase()),
    maliciousNpmVersions: parseMaliciousNpmVersions(npmVersionsContent),
    wallets: parseWalletFile(walletsContent),
    blockchainAllowlist: parseIOCFile(blockchainContent, (extId) => extId),
    telemetryServices: parseTelemetryServices(telemetryContent),
    githubC2Accounts: parseIOCFile(githubC2Content, (username) => username.toLowerCase()),
  };
}
