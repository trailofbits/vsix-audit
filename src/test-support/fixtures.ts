import type { VsixContents, VsixManifest, ZooData } from "#internal/scanner/types.js";

/** Build an in-memory extension without executing its source. */
export function makeContents(
  files: Record<string, string>,
  manifestOverrides: Partial<VsixManifest> = {},
): VsixContents {
  const manifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
    ...manifestOverrides,
  };
  return {
    manifest,
    basePath: "/test",
    files: new Map(Object.entries(files).map(([name, content]) => [name, Buffer.from(content)])),
  };
}

/** Start each test with independent threat-intelligence collections. */
export function makeZooData(overrides: Partial<ZooData> = {}): ZooData {
  return {
    blocklist: [],
    hashes: new Set(),
    domains: new Set(),
    ips: new Set(),
    maliciousNpmPackages: new Set(),
    maliciousNpmVersions: new Map(),
    wallets: new Set(),
    blockchainAllowlist: new Set(),
    telemetryServices: new Map(),
    githubC2Accounts: new Set(),
    ...overrides,
  };
}
