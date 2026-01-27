import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { computeSha256, loadDirectory, loadExtension } from "./vsix.js";

describe("computeSha256", () => {
  it("computes correct hash for buffer", () => {
    const content = Buffer.from("test content");
    const hash = computeSha256(content);

    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(hash).toBe("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72");
  });

  it("returns different hashes for different content", () => {
    const hash1 = computeSha256(Buffer.from("content1"));
    const hash2 = computeSha256(Buffer.from("content2"));

    expect(hash1).not.toBe(hash2);
  });
});

describe("loadDirectory", () => {
  const testDir = join(tmpdir(), `vsix-audit-test-${Date.now()}`);

  beforeAll(async () => {
    await mkdir(testDir, { recursive: true });
    await mkdir(join(testDir, "src"), { recursive: true });

    const manifest = {
      name: "test-extension",
      publisher: "test-publisher",
      version: "1.0.0",
      main: "./src/extension.js",
      activationEvents: ["onCommand:test.command"],
    };

    await writeFile(join(testDir, "package.json"), JSON.stringify(manifest, null, 2));
    await writeFile(join(testDir, "src", "extension.js"), 'console.log("hello");');
    await writeFile(join(testDir, "README.md"), "# Test Extension");
  });

  afterAll(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it("loads extension from directory", async () => {
    const contents = await loadDirectory(testDir);

    expect(contents.manifest.name).toBe("test-extension");
    expect(contents.manifest.publisher).toBe("test-publisher");
    expect(contents.manifest.version).toBe("1.0.0");
    expect(contents.basePath).toBe(testDir);
  });

  it("loads all files from directory", async () => {
    const contents = await loadDirectory(testDir);

    expect(contents.files.has("package.json")).toBe(true);
    expect(contents.files.has("src/extension.js")).toBe(true);
    expect(contents.files.has("README.md")).toBe(true);
  });

  it("excludes node_modules and .git directories", async () => {
    // Create node_modules and .git directories
    await mkdir(join(testDir, "node_modules", "dep"), { recursive: true });
    await mkdir(join(testDir, ".git", "objects"), { recursive: true });
    await writeFile(join(testDir, "node_modules", "dep", "index.js"), "module.exports = {};");
    await writeFile(join(testDir, ".git", "objects", "abc"), "git object");

    const contents = await loadDirectory(testDir);

    // Should not include node_modules or .git files
    expect([...contents.files.keys()].some((f) => f.includes("node_modules"))).toBe(false);
    expect([...contents.files.keys()].some((f) => f.includes(".git"))).toBe(false);
  });

  it("throws error for directory without package.json", async () => {
    const emptyDir = join(tmpdir(), `vsix-audit-empty-${Date.now()}`);
    await mkdir(emptyDir, { recursive: true });

    try {
      await expect(loadDirectory(emptyDir)).rejects.toThrow("missing package.json");
    } finally {
      await rm(emptyDir, { recursive: true, force: true });
    }
  });
});

describe("loadExtension", () => {
  const testDir = join(tmpdir(), `vsix-audit-load-test-${Date.now()}`);

  beforeAll(async () => {
    await mkdir(testDir, { recursive: true });
    const manifest = {
      name: "load-test",
      publisher: "test",
      version: "2.0.0",
    };
    await writeFile(join(testDir, "package.json"), JSON.stringify(manifest));
  });

  afterAll(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it("loads directory when target is a directory", async () => {
    const contents = await loadExtension(testDir);

    expect(contents.manifest.name).toBe("load-test");
    expect(contents.manifest.version).toBe("2.0.0");
  });

  it("throws error for unsupported file type", async () => {
    const invalidFile = join(tmpdir(), "invalid.txt");
    await writeFile(invalidFile, "not a vsix");

    try {
      await expect(loadExtension(invalidFile)).rejects.toThrow("Unsupported target");
    } finally {
      await rm(invalidFile, { force: true });
    }
  });
});
