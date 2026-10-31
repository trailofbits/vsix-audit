import { cp, mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hasCoverageExitFailure } from "#internal/scan-options.js";
import { scanExtension } from "#internal/scanner/index.js";
import type { ScanOptions } from "#internal/scanner/types.js";
import { loadZooData } from "#internal/scanner/loaders/zoo.js";

const bundledZoo = join(import.meta.dirname, "..", "..", "zoo");
afterEach(() => vi.unstubAllEnvs());

describe("required detection coverage", () => {
  it.each(["{}", '{"packages":null}', '{"packages":{}}'])(
    "rejects malformed package advisory datasets: %s",
    async (content) => {
      const root = await mkdtemp(join(tmpdir(), "vsix-invalid-data-"));
      try {
        await cp(bundledZoo, root, { recursive: true });
        await writeFile(join(root, "iocs/malicious-npm-versions.json"), content);
        await expect(loadZooData(root)).rejects.toThrow('field "packages" must be an array');
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  it.each([
    "telemetry/known-services.txt",
    "iocs/github-c2.txt",
    "iocs/malicious-npm-versions.json",
  ])("rejects a missing required dataset %s", async (file) => {
    const root = await mkdtemp(join(tmpdir(), "vsix-required-data-"));
    try {
      await cp(bundledZoo, root, { recursive: true });
      await unlink(join(root, file));
      await expect(loadZooData(root)).rejects.toThrow(
        `Cannot load detection dataset ${join(root, file)}`,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each(["", "rule BROKEN { condition: ??? }"])(
    "retains incomplete YARA coverage when low-severity findings are filtered",
    async (rule) => {
      const root = await mkdtemp(join(tmpdir(), "vsix-yara-coverage-"));
      try {
        const zoo = join(root, "zoo");
        await cp(bundledZoo, zoo, { recursive: true });
        const rules = join(zoo, "signatures", "yara");
        await rm(rules, { recursive: true });
        await mkdir(rules);
        if (rule !== "") await writeFile(join(rules, "broken.yar"), rule);
        vi.stubEnv("VSIX_AUDIT_ZOO_PATH", zoo);
        const target = join(root, "extension");
        await mkdir(target);
        await writeFile(
          join(target, "package.json"),
          JSON.stringify({ name: "fixture", version: "1.0.0" }),
        );
        const options: ScanOptions = {
          output: "json",
          severity: "critical",
          modules: ["yara"],
          strict: true,
          requireYara: true,
        };
        const result = await scanExtension(target, { ...options, modules: ["yara"] });
        expect(result.findings).toEqual([]);
        expect(result.metadata.coverage).toMatchObject({
          degraded: true,
          incompleteModules: ["yara"],
        });
        expect(result.metadata.coverage.warnings.length).toBeGreaterThan(0);
        expect(hasCoverageExitFailure(result, options)).toBe(true);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
