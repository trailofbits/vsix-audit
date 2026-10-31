import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadZooData } from "#internal/scanner/loaders/zoo.js";
import type { ZooData } from "#internal/scanner/types.js";

const boundary = vi.hoisted(() => ({
  beforeRead: async (_path: unknown): Promise<void> => {},
}));
vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return {
    ...fs,
    readFile: async (...args: Parameters<typeof fs.readFile>): ReturnType<typeof fs.readFile> => {
      await boundary.beforeRead(args[0]);
      return fs.readFile(...args);
    },
  };
});

afterEach(() => {
  boundary.beforeRead = async (): Promise<void> => {};
});

const bundledZoo = join(import.meta.dirname, "..", "..", "..", "zoo");

describe("concurrent dataset roots", () => {
  it("keeps a loaded root available when an older root fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "vsix-root-race-"));
    const slow = join(root, "slow");
    const current = join(root, "current");
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let failed: Promise<ZooData> | undefined;
    let currentUnavailable = false;
    try {
      await cp(bundledZoo, slow, { recursive: true });
      await cp(bundledZoo, current, { recursive: true });
      const blocked = join(slow, "iocs/github-c2.txt");
      boundary.beforeRead = async (path): Promise<void> => {
        if (String(path) === blocked) {
          await gate;
          throw new Error("Older root read failed");
        }
        if (currentUnavailable && String(path).startsWith(current)) {
          throw new Error("Current filesystem unavailable");
        }
      };
      failed = loadZooData(slow);
      const failure = failed.catch((error: unknown): unknown => error);
      expect((await loadZooData(current)).githubC2Accounts.size).toBeGreaterThan(0);
      currentUnavailable = true;
      release();
      const error = await failure;
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toContain(`Cannot load detection dataset ${blocked}`);
      expect((await loadZooData(current)).githubC2Accounts.size).toBeGreaterThan(0);
    } finally {
      release();
      await Promise.allSettled(failed === undefined ? [] : [failed]);
      await rm(root, { recursive: true, force: true });
    }
  });
});
