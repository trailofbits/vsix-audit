import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import type { Registry } from "./types.js";

const APP_NAME = "vsix-audit";

export interface CachedExtension {
  registry: Registry;
  publisher: string;
  name: string;
  version: string;
  path: string;
  size: number;
  cachedAt: Date;
}

/**
 * Get the XDG-compliant cache directory for vsix-audit
 *
 * - macOS: ~/Library/Caches/vsix-audit/
 * - Linux: $XDG_CACHE_HOME/vsix-audit/ or ~/.cache/vsix-audit/
 */
export function getCacheDir(): string {
  const os = platform();

  if (os === "darwin") {
    return join(homedir(), "Library", "Caches", APP_NAME);
  }

  // Linux and other Unix-like systems: respect XDG_CACHE_HOME
  const xdgCacheHome = process.env["XDG_CACHE_HOME"];
  if (xdgCacheHome) {
    return join(xdgCacheHome, APP_NAME);
  }

  return join(homedir(), ".cache", APP_NAME);
}

/**
 * Get the expected cache path for an extension
 */
export function getCachedPath(
  registry: Registry,
  publisher: string,
  name: string,
  version: string,
): string {
  const cacheDir = getCacheDir();
  const filename = `${publisher}.${name}-${version}.vsix`;
  return join(cacheDir, registry, filename);
}

/**
 * Parse a cached VSIX filename into its components
 */
function parseVsixFilename(
  filename: string,
): { publisher: string; name: string; version: string } | null {
  // Format: publisher.name-version.vsix
  const match = filename.match(/^(.+?)\.(.+)-(.+)\.vsix$/);
  if (!match) {
    return null;
  }

  const [, publisher, name, version] = match;
  if (!publisher || !name || !version) {
    return null;
  }

  return { publisher, name, version };
}

/**
 * Check if an extension is already cached
 */
export async function isCached(
  registry: Registry,
  publisher: string,
  name: string,
  version: string,
): Promise<boolean> {
  const cachedPath = getCachedPath(registry, publisher, name, version);
  try {
    await stat(cachedPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * List all cached extensions
 */
export async function listCached(): Promise<CachedExtension[]> {
  const cacheDir = getCacheDir();
  const extensions: CachedExtension[] = [];

  const registries: Registry[] = ["marketplace", "openvsx", "cursor"];

  for (const registry of registries) {
    const registryDir = join(cacheDir, registry);

    let files: string[];
    try {
      files = await readdir(registryDir);
    } catch {
      // Directory doesn't exist
      continue;
    }

    for (const file of files) {
      if (!file.endsWith(".vsix")) {
        continue;
      }

      const parsed = parseVsixFilename(file);
      if (!parsed) {
        continue;
      }

      const filePath = join(registryDir, file);
      try {
        const fileStat = await stat(filePath);
        extensions.push({
          registry,
          publisher: parsed.publisher,
          name: parsed.name,
          version: parsed.version,
          path: filePath,
          size: fileStat.size,
          cachedAt: fileStat.mtime,
        });
      } catch {
        // File was removed between readdir and stat
        continue;
      }
    }
  }

  // Sort by cached date, newest first
  extensions.sort((a, b) => b.cachedAt.getTime() - a.cachedAt.getTime());

  return extensions;
}

/**
 * Clear cached extensions, optionally matching a pattern
 *
 * @param pattern - Optional glob-like pattern (e.g., "ms-python.*" or "*.python")
 * @returns Number of files deleted
 */
export async function clearCache(pattern?: string): Promise<number> {
  const extensions = await listCached();
  let deleted = 0;

  for (const ext of extensions) {
    const extensionId = `${ext.publisher}.${ext.name}`;

    // Check if extension matches pattern
    if (pattern) {
      // Escape all regex metacharacters except * (which becomes .*)
      const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
      const regexStr = escaped.replace(/\*/g, ".*");
      const regex = new RegExp("^" + regexStr + "$");
      if (!regex.test(extensionId)) {
        continue;
      }
    }

    try {
      await rm(ext.path);
      deleted++;
    } catch {
      // File may have been deleted
    }
  }

  return deleted;
}

/** Default TTL for cached extensions: 14 days in milliseconds */
const DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Evict cached extensions older than the given TTL.
 *
 * Uses file mtime to determine age. Runs opportunistically
 * and silently ignores errors (files already deleted, etc.).
 *
 * @param ttlMs - Max age in milliseconds (default: 14 days)
 * @returns Number of files evicted
 */
export async function evictStaleEntries(ttlMs: number = DEFAULT_TTL_MS): Promise<number> {
  const extensions = await listCached();
  const cutoff = Date.now() - ttlMs;
  let evicted = 0;

  for (const ext of extensions) {
    if (ext.cachedAt.getTime() < cutoff) {
      try {
        await rm(ext.path);
        evicted++;
      } catch {
        // File may have been deleted already
      }
    }
  }

  return evicted;
}

/**
 * Ensure the cache directory exists for a registry
 */
export async function ensureCacheDir(registry: Registry): Promise<string> {
  const dir = join(getCacheDir(), registry);
  await mkdir(dir, { recursive: true });
  return dir;
}

/**
 * Get info about cached versions of an extension
 */
export async function getCachedVersions(
  publisher: string,
  name: string,
): Promise<CachedExtension[]> {
  const allCached = await listCached();
  return allCached.filter((ext) => ext.publisher === publisher && ext.name === name);
}
