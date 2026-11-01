import type { Dirent } from "node:fs";
import { lstat, readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { BatchScanResult, InstalledScanScope } from "#internal/scanner/types.js";

export const INSTALLED_EDITORS = ["vscode", "insiders", "cursor", "all"] as const;
export type InstalledEditor = (typeof INSTALLED_EDITORS)[number];

export interface InstalledDiscoveryOptions {
  editor: InstalledEditor;
  extensionsDir?: string;
}

export interface InstalledDiscoveryResult extends InstalledScanScope {
  paths: string[];
  errors: BatchScanResult["errors"];
}

const INSTALLED_SCOPE =
  "All on-disk versions in the listed local stores, including disabled " +
  "and obsolete versions. Active profiles and remote extension hosts are not enumerated; " +
  "use --extensions-dir for other stores mounted locally.";

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

function configuredVsCodeStore(): string | undefined {
  const configured = process.env["VSCODE_EXTENSIONS"];
  if (configured !== undefined && configured !== "") return resolve(configured);
  const portable = process.env["VSCODE_PORTABLE"];
  if (portable !== undefined && portable !== "") return join(resolve(portable), "extensions");
  return undefined;
}

function extensionStores(
  options: InstalledDiscoveryOptions,
): Array<{ path: string; optional: boolean }> {
  if (options.extensionsDir !== undefined) {
    return [{ path: customDirectory(options.extensionsDir), optional: false }];
  }
  const configured = options.editor === "cursor" ? undefined : configuredVsCodeStore();
  const editors =
    options.editor === "all" ? (["vscode", "insiders", "cursor"] as const) : [options.editor];
  const stores = new Map<string, boolean>();
  for (const editor of editors) {
    const override = editor !== "cursor" && configured !== undefined;
    const path = override ? configured : join(homedir(), EDITOR_DIRECTORIES[editor], "extensions");
    stores.set(path, !override);
  }
  return [...stores].map(([path, optional]) => ({ path, optional }));
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

async function storePaths(
  root: string,
  optional: boolean,
  errors: BatchScanResult["errors"],
): Promise<string[]> {
  const entries = await readStore(root, optional);
  const candidates = entries.filter(
    (entry) => !entry.name.startsWith(".") && (entry.isDirectory() || entry.isSymbolicLink()),
  );
  const paths: string[] = [];
  for (const entry of candidates) {
    const candidate = join(root, entry.name);
    try {
      const path = await resolveExtension(candidate);
      if (path !== undefined) paths.push(path);
    } catch (error) {
      errors.push({
        path: candidate,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return paths;
}

/**
 * Find extension directories in the selected user's editor stores.
 *
 * Returns each physical directory once, including all on-disk extension versions.
 * Missing default stores are skipped. Other discovery failures accompany healthy paths.
 */
export async function findInstalledExtensions(
  options: InstalledDiscoveryOptions,
): Promise<InstalledDiscoveryResult> {
  const stores = extensionStores(options);
  const roots = stores.map((store) => store.path);
  const errors: BatchScanResult["errors"] = [];
  const paths = new Set<string>();
  for (const store of stores) {
    try {
      const candidates = await storePaths(store.path, store.optional, errors);
      for (const path of candidates) paths.add(path);
    } catch (error) {
      errors.push({
        path: store.path,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  if (paths.size === 0 && errors.length === 0) {
    errors.push({
      path: roots.join(", "),
      error:
        `No installed extensions found in ${roots.join(", ")}. ` +
        "Choose another --editor or use --extensions-dir <path>.",
    });
  }
  return { paths: [...paths].sort(), errors, roots, scope: INSTALLED_SCOPE };
}
