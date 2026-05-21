import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import * as yauzl from "yauzl";
import type { VsixContents, VsixManifest } from "./types.js";

const VSIX_EXTENSION_PREFIX = "extension/";

/** Maximum uncompressed size for a single entry (500 MB). */
export const MAX_ENTRY_SIZE = 500 * 1024 * 1024;

/** Maximum total extracted size across all entries (1 GB). */
export const MAX_TOTAL_SIZE = 1024 * 1024 * 1024;

/** Maximum compression ratio before flagging as suspicious. */
export const MAX_COMPRESSION_RATIO = 100;

/**
 * Validate that a ZIP entry path is safe (no path traversal).
 * Prevents zip slip attacks by rejecting paths with ".." segments.
 */
function isPathSafe(path: string): boolean {
  if (path.includes("\\")) return false;
  const normalized = path.split("/").filter((p) => p !== ".");
  return !normalized.some((segment) => segment === ".." || segment.startsWith(".."));
}

function openZipFile(vsixPath: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(
      vsixPath,
      {
        autoClose: false,
        lazyEntries: true,
        decodeStrings: true,
        validateEntrySizes: false,
      },
      (error, zipFile) => {
        if (error) {
          reject(error);
          return;
        }
        if (!zipFile) {
          reject(new Error("Invalid ZIP: failed to open archive"));
          return;
        }
        resolve(zipFile);
      },
    );
  });
}

function collectZipEntries(zipFile: yauzl.ZipFile): Promise<yauzl.Entry[]> {
  return new Promise((resolve, reject) => {
    const entries: yauzl.Entry[] = [];

    zipFile.once("error", reject);
    zipFile.on("entry", (entry) => {
      entries.push(entry);
      zipFile.readEntry();
    });
    zipFile.once("end", () => resolve(entries));
    zipFile.readEntry();
  });
}

function openZipEntryStream(
  zipFile: yauzl.ZipFile,
  entry: yauzl.Entry,
): Promise<NodeJS.ReadableStream> {
  return new Promise((resolve, reject) => {
    zipFile.openReadStream(entry, (error, stream) => {
      if (error) {
        reject(error);
        return;
      }
      if (!stream) {
        reject(new Error(`Failed to read ZIP entry "${entry.fileName}"`));
        return;
      }
      resolve(stream);
    });
  });
}

async function readZipEntry(entry: yauzl.Entry, zipFile: yauzl.ZipFile): Promise<Buffer> {
  const stream = await openZipEntryStream(zipFile, entry);
  const chunks: Buffer[] = [];
  let actualSize = 0;

  for await (const chunk of stream) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    actualSize += data.length;
    if (actualSize > MAX_ENTRY_SIZE) {
      throw new Error(`ZIP entry "${entry.fileName}" exceeds ${MAX_ENTRY_SIZE} byte limit`);
    }
    chunks.push(data);
  }

  return Buffer.concat(chunks);
}

export async function extractVsix(vsixPath: string): Promise<VsixContents> {
  const zipFile = await openZipFile(vsixPath);
  const files = new Map<string, Buffer>();
  const warnings: string[] = [];

  let manifest: VsixManifest | undefined;
  let totalExtractedSize = 0;

  try {
    const entries = await collectZipEntries(zipFile);

    for (const entry of entries) {
      if (entry.fileName.endsWith("/")) {
        continue;
      }

      if (!isPathSafe(entry.fileName)) {
        throw new Error(`Invalid VSIX: path traversal detected in "${entry.fileName}"`);
      }

      if (entry.uncompressedSize > MAX_ENTRY_SIZE) {
        warnings.push(
          `Skipped "${entry.fileName}": declared size ` +
            `${entry.uncompressedSize} exceeds ` +
            `${MAX_ENTRY_SIZE} byte limit`,
        );
        continue;
      }

      if (
        entry.compressedSize > 0 &&
        entry.uncompressedSize / entry.compressedSize > MAX_COMPRESSION_RATIO
      ) {
        warnings.push(
          `Skipped "${entry.fileName}": compression ratio ` +
            `${Math.round(entry.uncompressedSize / entry.compressedSize)}:1 ` +
            `exceeds ${MAX_COMPRESSION_RATIO}:1 limit`,
        );
        continue;
      }

      if (totalExtractedSize + entry.uncompressedSize > MAX_TOTAL_SIZE) {
        warnings.push(
          `Skipped "${entry.fileName}": total extracted size would ` +
            `exceed ${MAX_TOTAL_SIZE} byte limit`,
        );
        continue;
      }

      totalExtractedSize += entry.uncompressedSize;
      let content: Buffer;
      try {
        content = await readZipEntry(entry, zipFile);
      } catch (error) {
        warnings.push(
          `Skipped "${entry.fileName}": failed to extract entry ` +
            `(${error instanceof Error ? error.message : String(error)})`,
        );
        continue;
      }

      let relativePath = entry.fileName;
      if (relativePath.startsWith(VSIX_EXTENSION_PREFIX)) {
        relativePath = relativePath.slice(VSIX_EXTENSION_PREFIX.length);
      }

      files.set(relativePath, content);

      if (relativePath === "package.json") {
        manifest = JSON.parse(content.toString("utf8")) as VsixManifest;
      }
    }
  } finally {
    zipFile.close();
  }

  if (!manifest) {
    manifest = findManifestWithNonStandardPrefix(files);
  }

  if (!manifest) {
    throw new Error("Invalid VSIX: missing package.json");
  }

  return {
    manifest,
    files,
    basePath: vsixPath,
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}

/**
 * Find package.json under a non-standard prefix
 * (e.g. "publisher.name-version/" instead of "extension/")
 * and re-normalize all paths.
 */
function findManifestWithNonStandardPrefix(files: Map<string, Buffer>): VsixManifest | undefined {
  for (const [path, content] of files) {
    const match = path.match(/^([^/]+)\/package\.json$/);
    if (!match) {
      continue;
    }

    const prefix = match[1] + "/";
    const normalized = new Map<string, Buffer>();

    for (const [p, c] of files) {
      if (p.startsWith(prefix)) {
        normalized.set(p.slice(prefix.length), c);
      } else {
        normalized.set(p, c);
      }
    }

    files.clear();
    for (const [p, c] of normalized) {
      files.set(p, c);
    }

    return JSON.parse(content.toString("utf8")) as VsixManifest;
  }

  return undefined;
}

export async function loadDirectory(dirPath: string): Promise<VsixContents> {
  const files = new Map<string, Buffer>();

  async function walkDir(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.name === "node_modules" || entry.name === ".git") {
        continue;
      }

      if (entry.isDirectory()) {
        await walkDir(fullPath);
      } else if (entry.isFile()) {
        const relativePath = relative(dirPath, fullPath);
        const content = await readFile(fullPath);
        files.set(relativePath, content);
      }
    }
  }

  await walkDir(dirPath);

  const manifestBuffer = files.get("package.json");
  if (!manifestBuffer) {
    throw new Error("Invalid extension directory: missing package.json");
  }

  const manifest = JSON.parse(manifestBuffer.toString("utf8")) as VsixManifest;

  return {
    manifest,
    files,
    basePath: dirPath,
  };
}

export async function loadExtension(target: string): Promise<VsixContents> {
  const stats = await stat(target);

  if (stats.isDirectory()) {
    return loadDirectory(target);
  } else if (target.endsWith(".vsix")) {
    return extractVsix(target);
  } else {
    throw new Error(`Unsupported target: ${target}. Expected .vsix file or directory.`);
  }
}

export function computeSha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
