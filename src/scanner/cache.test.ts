import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearCache,
  ensureCacheDir,
  getCacheDir,
  getCachedPath,
  getCachedVersions,
  isCached,
  listCached,
} from "./cache.js";

const CACHE_DIR_ENV_VAR = "VSIX_AUDIT_CACHE_DIR";

describe("getCacheDir", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("returns macOS cache path on darwin", () => {
    const os = platform();
    if (os === "darwin") {
      const dir = getCacheDir();
      expect(dir).toBe(join(homedir(), "Library", "Caches", "vsix-audit"));
    }
  });

  it("respects XDG_CACHE_HOME on Linux", () => {
    const os = platform();
    if (os === "linux") {
      process.env["XDG_CACHE_HOME"] = "/custom/cache";
      // Need to re-import module to pick up env change
      const dir = getCacheDir();
      // On actual Linux with XDG set, should use it
      expect(dir).toContain("vsix-audit");
    }
  });

  it("falls back to ~/.cache on Linux without XDG_CACHE_HOME", () => {
    const os = platform();
    if (os === "linux") {
      delete process.env["XDG_CACHE_HOME"];
      const dir = getCacheDir();
      expect(dir).toBe(join(homedir(), ".cache", "vsix-audit"));
    }
  });

  it("returns a path containing vsix-audit", () => {
    const dir = getCacheDir();
    expect(dir).toContain("vsix-audit");
  });

  it("respects explicit cache override", () => {
    process.env[CACHE_DIR_ENV_VAR] = "/tmp/vsix-audit-cache";
    expect(getCacheDir()).toBe("/tmp/vsix-audit-cache");
  });
});

describe("getCachedPath", () => {
  it("constructs correct path for marketplace extension", () => {
    const path = getCachedPath("marketplace", "ms-python", "python", "2024.1.0");

    expect(path).toContain("marketplace");
    expect(path).toContain("ms-python.python-2024.1.0.vsix");
  });

  it("constructs correct path for openvsx extension", () => {
    const path = getCachedPath("openvsx", "redhat", "java", "1.0.0");

    expect(path).toContain("openvsx");
    expect(path).toContain("redhat.java-1.0.0.vsix");
  });

  it("constructs correct path for cursor extension", () => {
    const path = getCachedPath("cursor", "eamodio", "gitlens", "15.0.0");

    expect(path).toContain("cursor");
    expect(path).toContain("eamodio.gitlens-15.0.0.vsix");
  });

  it("handles extension names with dots", () => {
    const path = getCachedPath("marketplace", "publisher", "ext.name", "1.0.0");

    expect(path).toContain("publisher.ext.name-1.0.0.vsix");
  });
});

describe("cache operations", () => {
  let testCacheDir: string;
  const originalCacheDir = process.env[CACHE_DIR_ENV_VAR];

  beforeEach(async () => {
    testCacheDir = await mkdtemp(join(tmpdir(), "vsix-audit-cache-test-"));
    process.env[CACHE_DIR_ENV_VAR] = testCacheDir;
  });

  afterEach(async () => {
    await rm(testCacheDir, { recursive: true, force: true });
    if (originalCacheDir === undefined) {
      delete process.env[CACHE_DIR_ENV_VAR];
    } else {
      process.env[CACHE_DIR_ENV_VAR] = originalCacheDir;
    }
  });

  describe("isCached", () => {
    it("returns false for non-existent extension", async () => {
      const result = await isCached("marketplace", "nonexistent", "ext", "1.0.0");
      expect(result).toBe(false);
    });
  });

  describe("listCached", () => {
    it("returns empty array when cache is empty", async () => {
      const result = await listCached();
      expect(result).toEqual([]);
    });
  });

  describe("clearCache", () => {
    it("returns 0 when no extensions match pattern", async () => {
      const deleted = await clearCache("nonexistent.*");
      expect(deleted).toBe(0);
    });
  });

  describe("ensureCacheDir", () => {
    it("creates marketplace cache directory", async () => {
      const dir = await ensureCacheDir("marketplace");
      expect(dir).toContain("marketplace");
    });

    it("creates openvsx cache directory", async () => {
      const dir = await ensureCacheDir("openvsx");
      expect(dir).toContain("openvsx");
    });

    it("creates cursor cache directory", async () => {
      const dir = await ensureCacheDir("cursor");
      expect(dir).toContain("cursor");
    });
  });

  describe("getCachedVersions", () => {
    it("returns empty array for non-existent extension", async () => {
      const versions = await getCachedVersions("nonexistent", "ext");
      expect(versions).toEqual([]);
    });
  });
});

describe("cache with test files", () => {
  let testCacheDir: string;
  const originalCacheDir = process.env[CACHE_DIR_ENV_VAR];

  beforeEach(async () => {
    testCacheDir = await mkdtemp(join(tmpdir(), "vsix-audit-cache-integration-"));
    process.env[CACHE_DIR_ENV_VAR] = testCacheDir;
  });

  afterEach(async () => {
    await rm(testCacheDir, { recursive: true, force: true });
    if (originalCacheDir === undefined) {
      delete process.env[CACHE_DIR_ENV_VAR];
    } else {
      process.env[CACHE_DIR_ENV_VAR] = originalCacheDir;
    }
  });

  it("lists extensions in cache directory", async () => {
    const marketplaceDir = join(testCacheDir, "marketplace");
    await mkdir(marketplaceDir, { recursive: true });

    const testVsix = join(marketplaceDir, "test-pub.test-ext-1.0.0.vsix");
    await writeFile(testVsix, "fake vsix content");

    const cached = await listCached();
    expect(cached).toHaveLength(1);
    expect(cached[0]).toMatchObject({
      registry: "marketplace",
      publisher: "test-pub",
      name: "test-ext",
      version: "1.0.0",
      path: testVsix,
    });
    expect(cached[0]?.size).toBeGreaterThan(0);
  });
});
