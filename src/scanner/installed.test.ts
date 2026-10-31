import * as fs from "node:fs/promises";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { findInstalledExtensions } from "#internal/scanner/installed.js";

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
});

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.mocked(fs.readdir).mockReset();
  vi.mocked(fs.realpath).mockReset();
  vi.mocked(fs.lstat).mockReset();
  await rm(home, { recursive: true, force: true });
});

describe("installed extension discovery", () => {
  it("finds all three editor stores and keeps every installed version", async () => {
    const paths = [
      join(home, ".vscode", "extensions", "test.first-1.0.0"),
      join(home, ".vscode", "extensions", "test.first-2.0.0"),
      join(home, ".vscode-insiders", "extensions", "test.second-1.0.0"),
      join(home, ".cursor", "extensions", "test.third-1.0.0"),
    ];
    for (const path of paths) await mkdir(path, { recursive: true });

    const found = await findInstalledExtensions({ editor: "all" });

    expect(found.toSorted()).toEqual(
      (await Promise.all(paths.map((path) => realpath(path)))).toSorted(),
    );
  });

  it.each([
    ["vscode", ".vscode"],
    ["insiders", ".vscode-insiders"],
    ["cursor", ".cursor"],
  ] as const)("limits discovery to %s", async (editor, directory) => {
    for (const root of [".vscode", ".vscode-insiders", ".cursor"]) {
      await mkdir(join(home, root, "extensions", "test.extension-1.0.0"), { recursive: true });
    }

    expect(await findInstalledExtensions({ editor })).toEqual([
      await realpath(join(home, directory, "extensions", "test.extension-1.0.0")),
    ]);
  });

  it("ignores metadata and staging folders without walking extension internals", async () => {
    const root = join(home, ".vscode", "extensions");
    const extension = join(root, "test.extension-1.0.0");
    await mkdir(join(extension, "nested"), { recursive: true });
    await mkdir(join(root, ".staging"));
    await writeFile(join(root, "extensions.json"), "[]");
    await writeFile(join(root, ".obsolete"), "{}");

    expect(await findInstalledExtensions({ editor: "all" })).toEqual([await realpath(extension)]);
  });

  it("deduplicates symbolic links to the same extension directory", async () => {
    const root = join(home, ".vscode", "extensions");
    const target = join(home, "development-extension");
    await mkdir(root, { recursive: true });
    await mkdir(target);
    await symlink(target, join(root, "test.first-1.0.0"), "junction");
    await symlink(target, join(root, "test.second-1.0.0"), "junction");

    expect(await findInstalledExtensions({ editor: "vscode" })).toEqual([await realpath(target)]);
  });

  // Windows file symlinks require privileges that directory junctions do not.
  it.skipIf(process.platform === "win32")("ignores symlinks to regular files", async () => {
    const root = join(home, ".vscode", "extensions");
    const extension = join(root, "test.extension-1.0.0");
    const metadata = join(home, "metadata.json");
    await mkdir(extension, { recursive: true });
    await writeFile(metadata, "{}");
    await symlink(metadata, join(root, "linked-metadata.json"));
    expect(await findInstalledExtensions({ editor: "vscode" })).toEqual([
      await realpath(extension),
    ]);
  });
});

describe("editor store combinations", () => {
  it("deduplicates editor stores pointing to the same physical extensions", async () => {
    const store = join(home, ".vscode", "extensions");
    const path = join(store, "test.extension-1.0.0");
    await mkdir(path, { recursive: true });
    await mkdir(join(home, ".cursor"));
    await symlink(store, join(home, ".cursor", "extensions"), "junction");
    expect(await findInstalledExtensions({ editor: "all" })).toEqual([await realpath(path)]);
  });

  it.each([1, 2, 3, 4, 5, 6, 7])("finds exactly the present stores for set %d", async (mask) => {
    const expected: string[] = [];
    const directories = [".vscode", ".vscode-insiders", ".cursor"];
    for (const [index, directory] of directories.entries()) {
      if ((mask & (1 << index)) === 0) continue;
      const path = join(home, directory, "extensions", "test.extension-1.0.0");
      await mkdir(path, { recursive: true });
      expected.push(await realpath(path));
    }
    expect(await findInstalledExtensions({ editor: "all" })).toEqual(expected.toSorted());
  });
});

describe("custom extension stores", () => {
  it("uses a custom directory without falling back to other stores", async () => {
    const root = join(home, "custom extensions");
    const extension = join(root, "test.custom-1.0.0");
    await mkdir(extension, { recursive: true });
    await mkdir(join(home, ".vscode", "extensions", "test.other-1.0.0"), {
      recursive: true,
    });

    expect(await findInstalledExtensions({ editor: "all", extensionsDir: root })).toEqual([
      await realpath(extension),
    ]);
  });

  it("expands a quoted home-relative custom path", async () => {
    const extension = join(home, "custom extensions", "test.extension-1.0.0");
    await mkdir(extension, { recursive: true });

    expect(
      await findInstalledExtensions({ editor: "all", extensionsDir: "~/custom extensions" }),
    ).toEqual([await realpath(extension)]);
  });
});

describe("installed discovery errors", () => {
  it("does not treat an uninspectable default store as missing", async () => {
    const error = Object.assign(new Error("permission denied"), { code: "EACCES" });
    vi.mocked(fs.lstat).mockRejectedValueOnce(error);
    await expect(findInstalledExtensions({ editor: "vscode" })).rejects.toThrow(
      /Cannot read.*extensions.*permission denied.*readable/,
    );
  });

  it("reports non-Error failures while reading a store", async () => {
    await mkdir(join(home, ".vscode", "extensions"), { recursive: true });
    vi.mocked(fs.readdir).mockRejectedValueOnce("reading failed");
    await expect(findInstalledExtensions({ editor: "vscode" })).rejects.toThrow(
      /Cannot read.*extensions.*reading failed.*readable/,
    );
  });

  it("reports permission errors without silently skipping a store", async () => {
    await mkdir(join(home, ".vscode", "extensions"), { recursive: true });
    const error = Object.assign(new Error("permission denied"), { code: "EACCES" });
    vi.mocked(fs.readdir).mockRejectedValueOnce(error);

    await expect(findInstalledExtensions({ editor: "vscode" })).rejects.toThrow(
      /Cannot read.*extensions.*permission denied.*readable/,
    );
  });

  it("reports a broken store symlink even when another editor has extensions", async () => {
    const root = join(home, ".vscode", "extensions");
    await mkdir(join(home, ".vscode"));
    await symlink(join(home, "missing-store"), root, "junction");
    await mkdir(join(home, ".cursor", "extensions", "test.extension-1.0.0"), {
      recursive: true,
    });
    await expect(findInstalledExtensions({ editor: "all" })).rejects.toThrow(root);
  });

  it("reports a failure while resolving an extension directory", async () => {
    const path = join(home, ".vscode", "extensions", "test.extension-1.0.0");
    await mkdir(path, { recursive: true });
    vi.mocked(fs.realpath).mockRejectedValueOnce("resolution failed");

    await expect(findInstalledExtensions({ editor: "vscode" })).rejects.toThrow(
      /Cannot inspect.*test.extension-1.0.0.*resolution failed.*retry/,
    );
  });
});

describe("invalid or empty extension stores", () => {
  it("reports missing stores instead of claiming a clean scan", async () => {
    await expect(findInstalledExtensions({ editor: "all" })).rejects.toThrow(
      /No installed extensions found.*--extensions-dir/s,
    );
  });

  it("reports an empty custom store", async () => {
    await expect(findInstalledExtensions({ editor: "all", extensionsDir: home })).rejects.toThrow(
      /No installed extensions found/,
    );
  });

  it("reports a missing custom store with its path", async () => {
    const missing = join(home, "missing");
    await expect(
      findInstalledExtensions({ editor: "all", extensionsDir: missing }),
    ).rejects.toThrow(missing);
  });

  it("rejects a file used as an extensions directory", async () => {
    const file = join(home, "file");
    await writeFile(file, "not a directory");
    await expect(findInstalledExtensions({ editor: "all", extensionsDir: file })).rejects.toThrow(
      /Check.*directory/,
    );
  });

  it("rejects an empty custom path", async () => {
    await expect(findInstalledExtensions({ editor: "all", extensionsDir: "" })).rejects.toThrow(
      /non-empty/,
    );
  });

  it("reports broken extension symlinks", async () => {
    const root = join(home, ".vscode", "extensions");
    const link = join(root, "test.broken-1.0.0");
    await mkdir(root, { recursive: true });
    await symlink(join(home, "missing"), link, "junction");

    await expect(findInstalledExtensions({ editor: "vscode" })).rejects.toThrow(link);
  });
});
