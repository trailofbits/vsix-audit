import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCachedPath } from "#internal/scanner/cache.js";
import {
  downloadExtension,
  getCursorDownloadUrl,
  getMarketplaceDownloadUrl,
  getOpenVSXDownloadUrl,
  parseExtensionId,
} from "#internal/scanner/download.js";

describe("downloadExtension cache behavior", () => {
  let testDir: string;
  let cachedPath: string;
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "vsix-audit-download-test-"));
    vi.stubEnv("VSIX_AUDIT_CACHE_DIR", join(testDir, "cache"));
    cachedPath = getCachedPath("openvsx", "test", "extension", "1.0.0");
    await mkdir(join(testDir, "cache", "openvsx"), { recursive: true });
    await writeFile(cachedPath, "cached VSIX");
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "https://open-vsx.org/api/test/extension") {
        return Response.json({ namespace: "test", name: "extension", version: "1.0.0" });
      }
      if (url.endsWith("/test.extension-1.0.0.vsix")) {
        return new Response("fresh VSIX");
      }
      throw new Error(`Unexpected URL: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    await rm(testDir, { recursive: true, force: true });
  });

  it("reuses a cached extension by default", async () => {
    const result = await downloadExtension("openvsx:test.extension");

    expect(result.fromCache).toBe(true);
    expect(await readFile(result.path, "utf8")).toBe("cached VSIX");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refreshes the persistent cache when forced", async () => {
    const result = await downloadExtension("openvsx:test.extension", { forceDownload: true });

    expect(result.fromCache).toBe(false);
    expect(result.path).toBe(cachedPath);
    expect(await readFile(cachedPath, "utf8")).toBe("fresh VSIX");
  });

  it("bypasses cached content without writing to the cache", async () => {
    const destDir = join(testDir, "downloads");
    const result = await downloadExtension("openvsx:test.extension", {
      useCache: false,
      destDir,
    });

    expect(result.fromCache).toBe(false);
    expect(result.path).toBe(join(destDir, "test.extension-1.0.0.vsix"));
    expect(await readFile(result.path, "utf8")).toBe("fresh VSIX");
    expect(await readFile(cachedPath, "utf8")).toBe("cached VSIX");
  });

  it("saves uncached downloads in the current directory by default", async () => {
    vi.spyOn(process, "cwd").mockReturnValue(testDir);

    const result = await downloadExtension("openvsx:test.extension", { useCache: false });

    expect(result.path).toBe(join(testDir, "test.extension-1.0.0.vsix"));
    expect(await readFile(result.path, "utf8")).toBe("fresh VSIX");
    expect(await readFile(cachedPath, "utf8")).toBe("cached VSIX");
  });

  it.each([false, true])("does not access the cache with an existing file=%s", async (existing) => {
    const emptyCache = join(testDir, "unused-cache");
    if (existing) await writeFile(emptyCache, "blocked persistent cache");
    vi.stubEnv("VSIX_AUDIT_CACHE_DIR", emptyCache);

    const result = await downloadExtension("openvsx:test.extension", {
      useCache: false,
      destDir: join(testDir, "downloads"),
    });

    expect(await readFile(result.path, "utf8")).toBe("fresh VSIX");
    await expect(readdir(emptyCache)).rejects.toMatchObject({
      code: existing ? "ENOTDIR" : "ENOENT",
    });
    const saved = await readFile(emptyCache, "utf8").catch((error: unknown) => {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
      throw error;
    });
    expect(saved).toBe(existing ? "blocked persistent cache" : undefined);
  });
});

describe("parseExtensionId", () => {
  it("parses publisher.name format", () => {
    const result = parseExtensionId("ms-python.python");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("marketplace");
  });

  it("parses publisher.name@version format", () => {
    const result = parseExtensionId("ms-python.python@2024.1.0");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBe("2024.1.0");
    expect(result.registry).toBe("marketplace");
  });

  it("parses publisher/name format", () => {
    const result = parseExtensionId("ms-python/python");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("marketplace");
  });

  it("parses publisher/name@version format", () => {
    const result = parseExtensionId("ms-python/python@2024.1.0");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBe("2024.1.0");
    expect(result.registry).toBe("marketplace");
  });

  it("handles dots in extension name", () => {
    const result = parseExtensionId("publisher.extension.name");

    expect(result.publisher).toBe("publisher");
    expect(result.name).toBe("extension.name");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("marketplace");
  });

  it("handles dots in slash-form extension names", () => {
    const result = parseExtensionId("publisher/extension.name");

    expect(result.publisher).toBe("publisher");
    expect(result.name).toBe("extension.name");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("marketplace");
  });

  it("handles version with dots", () => {
    const result = parseExtensionId("ms-vscode.cpptools@1.2.3");

    expect(result.publisher).toBe("ms-vscode");
    expect(result.name).toBe("cpptools");
    expect(result.version).toBe("1.2.3");
  });

  it("handles prerelease versions", () => {
    const result = parseExtensionId("publisher.ext@1.0.0-beta.1");

    expect(result.publisher).toBe("publisher");
    expect(result.name).toBe("ext");
    expect(result.version).toBe("1.0.0-beta.1");
  });

  it("parses openvsx: prefix", () => {
    const result = parseExtensionId("openvsx:redhat.java");

    expect(result.publisher).toBe("redhat");
    expect(result.name).toBe("java");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("openvsx");
  });

  it("parses openvsx: prefix with version", () => {
    const result = parseExtensionId("openvsx:redhat.java@1.0.0");

    expect(result.publisher).toBe("redhat");
    expect(result.name).toBe("java");
    expect(result.version).toBe("1.0.0");
    expect(result.registry).toBe("openvsx");
  });

  it("parses openvsx: prefix with slash-form ID", () => {
    const result = parseExtensionId("openvsx:redhat/java");

    expect(result.publisher).toBe("redhat");
    expect(result.name).toBe("java");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("openvsx");
  });

  it("parses marketplace: prefix", () => {
    const result = parseExtensionId("marketplace:ms-python.python");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("marketplace");
  });

  it("parses marketplace: prefix with version", () => {
    const result = parseExtensionId("marketplace:ms-python.python@2024.1.0");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBe("2024.1.0");
    expect(result.registry).toBe("marketplace");
  });

  it("parses marketplace: prefix with slash-form ID and version", () => {
    const result = parseExtensionId("marketplace:ms-python/python@2024.1.0");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBe("2024.1.0");
    expect(result.registry).toBe("marketplace");
  });

  it("parses cursor: prefix", () => {
    const result = parseExtensionId("cursor:ms-python.python");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBeUndefined();
    expect(result.registry).toBe("cursor");
  });

  it("parses cursor: prefix with version", () => {
    const result = parseExtensionId("cursor:ms-python.python@2024.1.0");

    expect(result.publisher).toBe("ms-python");
    expect(result.name).toBe("python");
    expect(result.version).toBe("2024.1.0");
    expect(result.registry).toBe("cursor");
  });

  it("throws on missing publisher", () => {
    expect(() => parseExtensionId("python")).toThrow("Invalid extension ID");
  });

  it("throws on empty publisher", () => {
    expect(() => parseExtensionId(".python")).toThrow("Invalid extension ID");
  });

  it("throws on empty name", () => {
    expect(() => parseExtensionId("publisher.")).toThrow("Invalid extension ID");
  });

  it("throws on empty slash-form publisher", () => {
    expect(() => parseExtensionId("/python")).toThrow("Invalid extension ID");
  });

  it("throws on empty slash-form name", () => {
    expect(() => parseExtensionId("publisher/")).toThrow("Invalid extension ID");
  });

  it("throws on slash-form ID with multiple slashes", () => {
    expect(() => parseExtensionId("publisher/extension/name")).toThrow("Invalid extension ID");
  });

  it("throws on just a dot", () => {
    expect(() => parseExtensionId(".")).toThrow("Invalid extension ID");
  });

  it("throws on openvsx: prefix with invalid ID", () => {
    expect(() => parseExtensionId("openvsx:invalid")).toThrow("Invalid extension ID");
  });
});

describe("getMarketplaceDownloadUrl", () => {
  it("generates correct Marketplace download URL", () => {
    const url = getMarketplaceDownloadUrl("ms-python", "python", "2024.1.0");

    expect(url).toBe(
      "https://ms-python.gallery.vsassets.io/_apis/public/gallery/publisher/ms-python/extension/python/2024.1.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
    );
  });
});

describe("getOpenVSXDownloadUrl", () => {
  it("generates correct OpenVSX download URL", () => {
    const url = getOpenVSXDownloadUrl("redhat", "java", "1.0.0");

    expect(url).toBe("https://open-vsx.org/api/redhat/java/1.0.0/file/redhat.java-1.0.0.vsix");
  });

  it("handles publisher with special chars", () => {
    const url = getOpenVSXDownloadUrl("ms-python", "python", "2024.1.0");

    expect(url).toBe(
      "https://open-vsx.org/api/ms-python/python/2024.1.0/file/ms-python.python-2024.1.0.vsix",
    );
  });
});

describe("getCursorDownloadUrl", () => {
  it("generates correct Cursor download URL", () => {
    const url = getCursorDownloadUrl("ms-python", "python", "2024.1.0");

    expect(url).toBe(
      "https://marketplace.cursorapi.com/_apis/public/gallery/publishers/ms-python/vsextensions/python/2024.1.0/vspackage",
    );
  });

  it("handles extension name with hyphen", () => {
    const url = getCursorDownloadUrl("eamodio", "gitlens", "15.0.0");

    expect(url).toBe(
      "https://marketplace.cursorapi.com/_apis/public/gallery/publishers/eamodio/vsextensions/gitlens/15.0.0/vspackage",
    );
  });
});
