import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanPaths } from "#internal/scanner/batch.js";
import type { ScanOptions } from "#internal/scanner/types.js";

const options: ScanOptions = {
  output: "json",
  severity: "low",
  network: false,
  modules: ["manifest"],
  intel: "none",
};

const timing = vi.hoisted(() => ({
  beforeStat: async (_path: unknown): Promise<void> => {},
  afterStat: (_path: unknown): void => {},
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    stat: async (...args: Parameters<typeof actual.stat>) => {
      await timing.beforeStat(args[0]);
      try {
        return await actual.stat(...args);
      } finally {
        timing.afterStat(args[0]);
      }
    },
  };
});

let root = "";

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-paths-"));
});

afterEach(async () => {
  timing.beforeStat = async () => {};
  timing.afterStat = () => {};
  await rm(root, { recursive: true, force: true });
});

async function extension(name: string): Promise<string> {
  const path = join(root, name);
  await mkdir(path);
  await writeFile(
    join(path, "package.json"),
    JSON.stringify({ name, publisher: "test", version: "1.0.0" }),
  );
  return path;
}

describe("scanPaths", () => {
  it("scans extracted extensions and preserves input order with concurrent workers", async () => {
    const paths = [await extension("second"), await extension("first")];
    const completed: number[] = [];
    const result = await scanPaths(
      paths,
      options,
      { onProgress: (count) => completed.push(count) },
      { concurrency: 2 },
    );

    expect(result.results.map((scan) => scan.extension.name)).toEqual(["second", "first"]);
    expect(result.summary).toMatchObject({ totalFiles: 2, scannedFiles: 2, failedFiles: 0 });
    expect(completed).toEqual([1, 2]);
  });

  it("keeps successes and errors in a mixed batch", async () => {
    const clean = await extension("clean");
    const missing = join(root, "missing");
    const errors: string[] = [];
    const progress: number[] = [];
    const result = await scanPaths([missing, clean], options, {
      onError: (path) => errors.push(path),
      onProgress: (count) => progress.push(count),
    });

    expect(result.results.map((scan) => scan.extension.name)).toEqual(["clean"]);
    expect(result.errors[0]?.path).toBe(missing);
    expect(result.summary).toMatchObject({ totalFiles: 2, scannedFiles: 1, failedFiles: 1 });
    expect(errors).toEqual([missing]);
    expect(progress).toEqual([1, 2]);
  });

  it("returns an empty batch for no paths", async () => {
    const result = await scanPaths([], options);
    expect(result.summary).toMatchObject({ totalFiles: 0, scannedFiles: 0, failedFiles: 0 });
    expect(result.results).toEqual([]);
  });

  it("validates scanner guarantees even for an empty batch", async () => {
    await expect(scanPaths([], { ...options, requireYara: true })).rejects.toThrow(
      "--require-yara cannot be used when the module filter excludes yara",
    );
  });

  it("reports non-Error rejections from a filesystem boundary", async () => {
    const path = await extension("broken");
    timing.beforeStat = vi
      .fn<() => Promise<void>>()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce("blocked");
    const batch = await scanPaths([path], options);
    expect(batch.errors).toEqual([{ path, error: "blocked" }]);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid concurrency %s",
    async (concurrency) => {
      await expect(scanPaths([], options, undefined, { concurrency })).rejects.toThrow(
        /concurrency.*positive.*integer/i,
      );
    },
  );
});

describe("scan worker bounds", () => {
  it.each([1, 2, 4, 8])("honors the concurrency bound %d", async (concurrency) => {
    const paths: string[] = [];
    for (let index = 0; index < 5; index++) paths.push(await extension(`extension-${index}`));
    let active = 0;
    let peak = 0;
    timing.beforeStat = async (path) => {
      if (!paths.includes(String(path))) return;
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
    };
    timing.afterStat = (path) => {
      if (paths.includes(String(path))) active--;
    };
    const batch = await scanPaths(paths, options, undefined, { concurrency });

    expect(batch.summary.scannedFiles).toBe(paths.length);
    expect(peak).toBe(Math.min(concurrency, paths.length));
    expect(active).toBe(0);
  });
});
