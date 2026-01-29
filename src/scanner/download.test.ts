import { describe, expect, it } from "vitest";
import {
  getDownloadUrl,
  getMarketplaceDownloadUrl,
  getOpenVSXDownloadUrl,
  parseExtensionId,
} from "./download.js";

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

  it("handles dots in extension name", () => {
    const result = parseExtensionId("publisher.extension.name");

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

  it("throws on missing publisher", () => {
    expect(() => parseExtensionId("python")).toThrow("Invalid extension ID");
  });

  it("throws on empty publisher", () => {
    expect(() => parseExtensionId(".python")).toThrow("Invalid extension ID");
  });

  it("throws on empty name", () => {
    expect(() => parseExtensionId("publisher.")).toThrow("Invalid extension ID");
  });

  it("throws on just a dot", () => {
    expect(() => parseExtensionId(".")).toThrow("Invalid extension ID");
  });

  it("throws on openvsx: prefix with invalid ID", () => {
    expect(() => parseExtensionId("openvsx:invalid")).toThrow("Invalid extension ID");
  });
});

describe("getDownloadUrl", () => {
  it("generates correct download URL", () => {
    const url = getDownloadUrl("ms-python", "python", "2024.1.0");

    expect(url).toBe(
      "https://ms-python.gallery.vsassets.io/_apis/public/gallery/publisher/ms-python/extension/python/2024.1.0/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
    );
  });

  it("handles publisher with hyphen", () => {
    const url = getDownloadUrl("ms-vscode", "cpptools", "1.0.0");

    expect(url).toContain("ms-vscode.gallery.vsassets.io");
    expect(url).toContain("/publisher/ms-vscode/");
  });

  it("handles extension name with special chars", () => {
    const url = getDownloadUrl("pub", "my-ext", "1.0.0");

    expect(url).toContain("/extension/my-ext/");
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

// Integration tests that require network access
describe.skip("downloadExtension (integration)", () => {
  // These tests are skipped by default as they require network access
  // Run manually with: npm test -- --run download.test.ts

  it("downloads a real extension", async () => {
    // This would actually download from the marketplace
    // Skipped to avoid network requests in normal test runs
  });

  it("queries extension metadata", async () => {
    // This would actually query the marketplace API
    // Skipped to avoid network requests in normal test runs
  });
});
