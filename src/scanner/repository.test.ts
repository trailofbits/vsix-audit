import { mkdtempDisposable, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanExtension, scanPaths } from "#internal/scanner/index.js";
import type { ScanOptions } from "#internal/scanner/types.js";
import {
  configureScanOptions,
  hasCoverageExitFailure,
  parseScanOptions,
} from "#internal/scan-options.js";
import type { CliScanOptions } from "#internal/scan-options.js";

const fetchMock = vi.fn<typeof fetch>();
const options: ScanOptions = { severity: "low", output: "json" };
async function writeExtension(path: string): Promise<void> {
  await writeFile(
    join(path, "package.json"),
    JSON.stringify({
      name: "fixture",
      publisher: "test",
      version: "1.0.0",
      repository: "example/source",
    }),
  );
}

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (): Promise<Response> =>
    Response.json([{ sha: "a".repeat(40) }]),
  );
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("GITHUB_TOKEN", "");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("repository scan selection", () => {
  it("keeps default scans offline", async () => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-offline-"));
    await writeExtension(root.path);
    const result = await scanExtension(root.path, options);
    expect(result.inventory.some((entry) => entry.name === "Repository")).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each<ScanOptions>([
    { ...options, checkRepository: true },
    { ...options, modules: ["repository"] },
  ])("runs repository checks when explicitly requested", async (selection) => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-enabled-"));
    await writeExtension(root.path);
    const result = await scanExtension(root.path, selection);
    expect(result.inventory).toContainEqual({
      name: "Repository",
      enabled: true,
      description: "Opt-in source repository accessibility and empty-repository checks",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("makes failed repository lookups explicit coverage failures under strict mode", async () => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-failure-"));
    await writeExtension(root.path);
    fetchMock.mockResolvedValue(new Response(null, { status: 503 }));
    const selection: ScanOptions = { ...options, modules: ["repository"], strict: true };
    const result = await scanExtension(root.path, selection);
    expect(result.findings).toEqual([]);
    expect(result.metadata.coverage).toMatchObject({
      degraded: true,
      incompleteModules: ["repository"],
    });
    expect(hasCoverageExitFailure(result, selection)).toBe(true);
  });

  it("shares repository lookups across concurrent batch scans", async () => {
    await using first = await mkdtempDisposable(join(tmpdir(), "vsix-repository-batch-"));
    await using second = await mkdtempDisposable(join(tmpdir(), "vsix-repository-batch-"));
    await Promise.all([writeExtension(first.path), writeExtension(second.path)]);
    const result = await scanPaths([first.path, second.path], {
      ...options,
      modules: ["repository"],
    });
    expect(result.errors).toEqual([]);
    expect(result.results).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});

describe("repository CLI options", () => {
  it("passes --check-repository through the shared CLI parser", () => {
    const command = configureScanOptions(new Command()).exitOverride();
    command.parse(["node", "test", "--check-repository"]);
    expect(parseScanOptions(command.opts<CliScanOptions>())).toMatchObject({
      checkRepository: true,
    });
  });

  it("disables repository lookups unless requested", () => {
    const command = configureScanOptions(new Command()).exitOverride();
    command.parse(["node", "test"]);
    expect(parseScanOptions(command.opts<CliScanOptions>())).toMatchObject({
      checkRepository: false,
    });
  });

  it("rejects a repository flag excluded by the module filter", () => {
    expect(() =>
      parseScanOptions({
        ...options,
        checkRepository: true,
        module: "ast",
      }),
    ).toThrow("module filter excludes repository");
  });
});
