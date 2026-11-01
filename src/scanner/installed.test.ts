import * as fs from "node:fs/promises";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  findInstalledExtensions,
  type InstalledDiscoveryOptions,
} from "#internal/scanner/installed.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    lstat: vi.fn<typeof actual.lstat>(actual.lstat),
    readdir: vi.fn<typeof actual.readdir>(actual.readdir),
    realpath: vi.fn<typeof actual.realpath>(actual.realpath),
  };
});

let home = "";
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "vsix-installed-"));
  vi.stubEnv("HOME", home);
  vi.stubEnv("USERPROFILE", home);
  vi.stubEnv("VSCODE_EXTENSIONS", undefined);
  vi.stubEnv("VSCODE_PORTABLE", undefined);
});
afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.mocked(fs.readdir).mockReset();
  vi.mocked(fs.realpath).mockReset();
  vi.mocked(fs.lstat).mockReset();
  await rm(home, { recursive: true, force: true });
});

async function extension(directory: string, name = "test.extension-1.0.0"): Promise<string> {
  const path = join(home, directory, "extensions", name);
  await mkdir(path, { recursive: true });
  return realpath(path);
}

async function foundPaths(options: InstalledDiscoveryOptions): Promise<string[]> {
  const result = await findInstalledExtensions(options);
  expect(result.errors).toEqual([]);
  return result.paths;
}

async function errorMessage(options: InstalledDiscoveryOptions): Promise<string> {
  const result = await findInstalledExtensions(options);
  expect(result.errors).toHaveLength(1);
  return result.errors.map((error) => error.error).join(" ");
}

describe("installed extension discovery", () => {
  it.each([1, 2, 3, 4, 5, 6, 7])("finds exactly the present stores for set %d", async (mask) => {
    const expected: string[] = [];
    const directories = [".vscode", ".vscode-insiders", ".cursor"];
    for (const [index, directory] of directories.entries()) {
      if ((mask & (1 << index)) === 0) continue;
      expected.push(await extension(directory));
    }
    expect(await foundPaths({ editor: "all" })).toEqual(expected.toSorted());
  });

  it.each([
    ["vscode", ".vscode"],
    ["insiders", ".vscode-insiders"],
    ["cursor", ".cursor"],
  ] as const)("limits discovery to %s and retains all versions", async (editor, directory) => {
    for (const store of [".vscode", ".vscode-insiders", ".cursor"]) await extension(store);
    const newer = await extension(directory, "test.extension-2.0.0");
    expect(await foundPaths({ editor })).toEqual(
      [
        await realpath(join(home, directory, "extensions", "test.extension-1.0.0")),
        newer,
      ].toSorted(),
    );
  });

  it("reports every searched root and states the inventory scope", async () => {
    await extension(".vscode");
    const result = await findInstalledExtensions({ editor: "all" });
    expect(result.roots).toEqual(
      [".vscode", ".vscode-insiders", ".cursor"].map((directory) =>
        join(home, directory, "extensions"),
      ),
    );
    expect(result.scope).toContain("disabled and obsolete");
    expect(result.scope).toContain("Active profiles and remote extension hosts");
  });

  it("ignores metadata and staging folders without walking extension internals", async () => {
    const installed = await extension(".vscode");
    const store = join(home, ".vscode", "extensions");
    await mkdir(join(installed, "nested"));
    await mkdir(join(store, ".staging"));
    await writeFile(join(store, "extensions.json"), "[]");
    await writeFile(join(store, ".obsolete"), "{}");
    expect(await foundPaths({ editor: "all" })).toEqual([installed]);
  });

  it("deduplicates extension symlinks and shared editor stores", async () => {
    const installed = await extension(".vscode");
    const store = join(home, ".vscode", "extensions");
    await symlink(installed, join(store, "test.link-1.0.0"), "junction");
    await mkdir(join(home, ".cursor"));
    await symlink(store, join(home, ".cursor", "extensions"), "junction");
    expect(await foundPaths({ editor: "all" })).toEqual([installed]);
  });

  // Windows file symlinks require privileges that directory junctions do not.
  it.skipIf(process.platform === "win32")("ignores symlinks to regular files", async () => {
    const installed = await extension(".vscode");
    const file = join(home, "metadata.json");
    await writeFile(file, "{}");
    await symlink(file, join(home, ".vscode", "extensions", "linked-metadata.json"));
    expect(await foundPaths({ editor: "vscode" })).toEqual([installed]);
  });
});

describe("configured extension stores", () => {
  it("uses an explicit directory before environment settings and defaults", async () => {
    const installed = await extension("custom extensions");
    await extension(".vscode");
    vi.stubEnv("VSCODE_EXTENSIONS", join(home, "missing-environment-store"));
    expect(
      await foundPaths({
        editor: "all",
        extensionsDir: join(home, "custom extensions", "extensions"),
      }),
    ).toEqual([installed]);
  });

  it("expands a quoted home-relative custom path", async () => {
    const installed = await extension("custom extensions");
    expect(
      await foundPaths({
        editor: "all",
        extensionsDir: "~/custom extensions/extensions",
      }),
    ).toEqual([installed]);
  });

  it.each(["vscode", "insiders"] as const)("honors VSCODE_EXTENSIONS for %s", async (editor) => {
    const installed = await extension("configured");
    await extension(".vscode");
    vi.stubEnv("VSCODE_EXTENSIONS", join(home, "configured", "extensions"));
    vi.stubEnv("VSCODE_PORTABLE", join(home, "unused-portable"));
    const result = await findInstalledExtensions({ editor });
    expect(result.paths).toEqual([installed]);
    expect(result.roots).toEqual([join(home, "configured", "extensions")]);
    expect(result.errors).toEqual([]);
  });

  it("uses portable extensions when no environment extension path is set", async () => {
    const installed = await extension("portable-data");
    vi.stubEnv("VSCODE_PORTABLE", join(home, "portable-data"));
    expect(await foundPaths({ editor: "vscode" })).toEqual([installed]);
  });

  it("deduplicates configured VS Code stores and keeps Cursor's own store", async () => {
    const configured = await extension("configured");
    const cursor = await extension(".cursor");
    vi.stubEnv("VSCODE_EXTENSIONS", join(home, "configured", "extensions"));
    const result = await findInstalledExtensions({ editor: "all" });
    expect(result.paths).toEqual([configured, cursor].toSorted());
    expect(result.roots).toHaveLength(2);
    expect(await foundPaths({ editor: "cursor" })).toEqual([cursor]);
  });

  it("reports a missing configured store rather than falling back to a default", async () => {
    await extension(".vscode");
    const missing = join(home, "missing-configured");
    vi.stubEnv("VSCODE_EXTENSIONS", missing);
    const result = await findInstalledExtensions({ editor: "vscode" });
    expect(result.paths).toEqual([]);
    expect(result.errors).toContainEqual(expect.objectContaining({ path: missing }));
  });
});

describe("partial discovery", () => {
  it("retains healthy extensions alongside a broken symlink", async () => {
    const installed = await extension(".vscode");
    const link = join(home, ".vscode", "extensions", "test.broken-1.0.0");
    await symlink(join(home, "missing"), link, "junction");
    const result = await findInstalledExtensions({ editor: "vscode" });
    expect(result.paths).toEqual([installed]);
    expect(result.errors).toMatchObject([{ path: link }]);
    expect(result.errors[0]?.error).toMatch(/repair/);
  });

  it("retains other editor stores when a store link is broken", async () => {
    const installed = await extension(".cursor");
    await mkdir(join(home, ".vscode"));
    const root = join(home, ".vscode", "extensions");
    await symlink(join(home, "missing-store"), root, "junction");
    const result = await findInstalledExtensions({ editor: "all" });
    expect(result.paths).toEqual([installed]);
    expect(result.errors).toMatchObject([{ path: root }]);
  });

  it.each([new Error("resolution denied"), "resolution failed"])(
    "records an extension resolution failure: %s",
    async (error) => {
      await extension(".vscode");
      vi.mocked(fs.realpath).mockRejectedValueOnce(error);
      const result = await findInstalledExtensions({ editor: "vscode" });
      expect(result.paths).toEqual([]);
      expect(result.errors).toMatchObject([
        {
          path: join(home, ".vscode", "extensions", "test.extension-1.0.0"),
        },
      ]);
      expect(result.errors[0]?.error).toMatch(/Cannot inspect.*resolution.*retry/);
    },
  );

  it("does not treat an uninspectable default store as missing", async () => {
    vi.mocked(fs.lstat).mockRejectedValueOnce(
      Object.assign(new Error("permission denied"), { code: "EACCES" }),
    );
    await expect(errorMessage({ editor: "vscode" })).resolves.toMatch(
      /Cannot read.*extensions.*permission denied.*readable/,
    );
  });

  it.each([new Error("permission denied"), "reading failed"])(
    "records store read failures: %s",
    async (error) => {
      await mkdir(join(home, ".vscode", "extensions"), { recursive: true });
      vi.mocked(fs.readdir).mockRejectedValueOnce(error);
      await expect(errorMessage({ editor: "vscode" })).resolves.toMatch(/Cannot read.*readable/);
    },
  );
});

describe("invalid or empty extension stores", () => {
  it("reports missing default stores and an empty custom store", async () => {
    await expect(errorMessage({ editor: "all" })).resolves.toMatch(
      /No installed extensions found.*--extensions-dir/s,
    );
    await expect(errorMessage({ editor: "all", extensionsDir: home })).resolves.toMatch(
      /No installed extensions found/,
    );
  });

  it("reports a missing explicit store", async () => {
    const missing = join(home, "missing");
    const result = await findInstalledExtensions({ editor: "all", extensionsDir: missing });
    expect(result.errors).toMatchObject([{ path: missing }]);
  });

  it("reports a file used as a store", async () => {
    const file = join(home, "file");
    await writeFile(file, "not a directory");
    await expect(errorMessage({ editor: "all", extensionsDir: file })).resolves.toMatch(
      /Check.*directory/,
    );
  });

  it.each(["", " "])("rejects an empty custom path %j", async (extensionsDir) => {
    await expect(findInstalledExtensions({ editor: "all", extensionsDir })).rejects.toThrow(
      /non-empty/,
    );
  });
});
