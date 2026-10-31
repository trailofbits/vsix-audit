import type { Dirent } from "node:fs";
import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export const INSTALLED_EDITORS = ["vscode", "insiders", "cursor", "all"] as const;
export type InstalledEditor = (typeof INSTALLED_EDITORS)[number];

export interface InstalledDiscoveryOptions {
  editor: InstalledEditor;
  extensionsDir?: string;
}

const EDITOR_DIRECTORIES = {
  vscode: ".vscode",
  insiders: ".vscode-insiders",
  cursor: ".cursor",
};

function customDirectory(path: string): string {
  if (path.trim() === "") {
    throw new Error("--extensions-dir must be a non-empty directory path.");
  }
  if (path === "~") return homedir();
  if (path.startsWith("~/") || path.startsWith("~\\")) {
    return resolve(homedir(), path.slice(2));
  }
  return resolve(path);
}

function defaultDirectories(editor: InstalledEditor): string[] {
  const directories =
    editor === "all" ? Object.values(EDITOR_DIRECTORIES) : [EDITOR_DIRECTORIES[editor]];
  return directories.map((directory) => join(homedir(), directory, "extensions"));
}

function isMissing(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

async function storeExists(root: string): Promise<boolean> {
  try {
    await lstat(root);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw error;
  }
}

async function readStore(root: string, optional: boolean): Promise<Dirent[]> {
  try {
    if (optional && !(await storeExists(root))) return [];
    return await readdir(root, { withFileTypes: true });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Cannot read installed extensions directory ${root}: ${reason}. ` +
        "Check that the directory exists and is readable, or use --extensions-dir <path>.",
      { cause: error },
    );
  }
}

async function resolveExtension(path: string): Promise<string | undefined> {
  try {
    if (!(await stat(path)).isDirectory()) return undefined;
    return await realpath(path);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Cannot inspect installed extension ${path}: ${reason}. ` +
        "Check the directory permissions and repair broken symbolic links, then retry.",
      { cause: error },
    );
  }
}

async function storePaths(root: string, optional: boolean): Promise<string[]> {
  const entries = await readStore(root, optional);
  const candidates = entries.filter(
    (entry) => !entry.name.startsWith(".") && (entry.isDirectory() || entry.isSymbolicLink()),
  );
  const paths: string[] = [];
  for (const entry of candidates) {
    const path = await resolveExtension(join(root, entry.name));
    if (path !== undefined) paths.push(path);
  }
  return paths;
}

/**
 * Find extension directories in the selected user's editor stores.
 *
 * Returns each physical directory once, including all on-disk extension versions.
 * Missing default stores are skipped; inaccessible stores and an empty inventory fail.
 */
export async function findInstalledExtensions(
  options: InstalledDiscoveryOptions,
): Promise<string[]> {
  const custom = options.extensionsDir !== undefined;
  const roots =
    options.extensionsDir === undefined
      ? defaultDirectories(options.editor)
      : [customDirectory(options.extensionsDir)];
  const paths = new Set<string>();
  for (const root of roots) {
    const candidates = await storePaths(root, !custom);
    for (const path of candidates) paths.add(path);
  }
  if (paths.size === 0) {
    throw new Error(
      `No installed extensions found in ${roots.join(", ")}. ` +
        "Choose another --editor or use --extensions-dir <path>.",
    );
  }
  return [...paths].sort();
}
