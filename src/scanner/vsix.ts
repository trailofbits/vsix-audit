import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";
import type { VsixContents, VsixManifest } from "./types.js";

const VSIX_EXTENSION_PREFIX = "extension/";
const LOCAL_FILE_HEADER = 0x04034b50;
const CENTRAL_DIR_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIR = 0x06054b50;

interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  dataOffset: number;
}

interface CentralDirEntry {
  fileName: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  localHeaderOffset: number;
}

/**
 * Find the End of Central Directory record by searching backwards from end of file.
 * The EOCD is at least 22 bytes and can have a variable-length comment.
 */
function findEndOfCentralDir(buffer: Buffer): number {
  // EOCD is minimum 22 bytes, max comment is 65535 bytes
  const minEocdOffset = Math.max(0, buffer.length - 22 - 65535);

  for (let i = buffer.length - 22; i >= minEocdOffset; i--) {
    if (buffer.readUInt32LE(i) === END_OF_CENTRAL_DIR) {
      return i;
    }
  }

  throw new Error("Invalid ZIP: End of central directory not found");
}

/**
 * Parse the central directory to get accurate file sizes.
 * Central directory always has correct sizes, even when local headers use data descriptors.
 */
function parseCentralDirectory(buffer: Buffer): Map<string, CentralDirEntry> {
  const eocdOffset = findEndOfCentralDir(buffer);
  const cdEntryCount = buffer.readUInt16LE(eocdOffset + 10);
  const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

  const entries = new Map<string, CentralDirEntry>();
  let offset = cdOffset;

  for (let i = 0; i < cdEntryCount; i++) {
    if (offset + 46 > buffer.length) {
      throw new Error("Invalid ZIP: Central directory entry extends beyond file");
    }

    if (buffer.readUInt32LE(offset) !== CENTRAL_DIR_HEADER) {
      throw new Error(`Invalid ZIP: Expected central directory header at offset ${offset}`);
    }

    const compressionMethod = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);

    if (offset + 46 + fileNameLength > buffer.length) {
      throw new Error("Invalid ZIP: File name extends beyond file");
    }

    const fileName = buffer.toString("utf8", offset + 46, offset + 46 + fileNameLength);

    // Skip directories (names ending with /)
    if (!fileName.endsWith("/")) {
      entries.set(fileName, {
        fileName,
        compressedSize,
        uncompressedSize,
        compressionMethod,
        localHeaderOffset,
      });
    }

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  return entries;
}

/**
 * Parse ZIP entries using the central directory for accurate sizes.
 * This handles ZIP files with data descriptors (bit 3 set) where local headers have size 0.
 */
function parseZipEntries(buffer: Buffer): ZipEntry[] {
  const centralDir = parseCentralDirectory(buffer);
  const entries: ZipEntry[] = [];

  for (const [fileName, cdEntry] of centralDir) {
    const offset = cdEntry.localHeaderOffset;

    if (offset + 30 > buffer.length) {
      throw new Error(`Invalid ZIP: Local header for ${fileName} extends beyond file`);
    }

    if (buffer.readUInt32LE(offset) !== LOCAL_FILE_HEADER) {
      throw new Error(`Invalid ZIP: Expected local file header for ${fileName}`);
    }

    const fileNameLength = buffer.readUInt16LE(offset + 26);
    const extraFieldLength = buffer.readUInt16LE(offset + 28);
    const dataOffset = offset + 30 + fileNameLength + extraFieldLength;

    entries.push({
      name: fileName,
      compressedSize: cdEntry.compressedSize,
      uncompressedSize: cdEntry.uncompressedSize,
      compressionMethod: cdEntry.compressionMethod,
      dataOffset,
    });
  }

  return entries;
}

function extractEntry(buffer: Buffer, entry: ZipEntry): Buffer {
  const compressedData = buffer.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);

  if (entry.compressionMethod === 0) {
    return compressedData;
  } else if (entry.compressionMethod === 8) {
    return inflateRawSync(compressedData);
  } else {
    throw new Error(`Unsupported compression method: ${entry.compressionMethod}`);
  }
}

export async function extractVsix(vsixPath: string): Promise<VsixContents> {
  const buffer = await readFile(vsixPath);
  const entries = parseZipEntries(buffer);
  const files = new Map<string, Buffer>();

  let manifest: VsixManifest | undefined;

  for (const entry of entries) {
    const content = extractEntry(buffer, entry);
    let relativePath = entry.name;

    if (relativePath.startsWith(VSIX_EXTENSION_PREFIX)) {
      relativePath = relativePath.slice(VSIX_EXTENSION_PREFIX.length);
    }

    files.set(relativePath, content);

    if (relativePath === "package.json") {
      manifest = JSON.parse(content.toString("utf8")) as VsixManifest;
    }
  }

  // Handle non-standard prefixes (e.g., "publisher.name-version/" instead of "extension/")
  if (!manifest) {
    for (const [path, content] of files) {
      const match = path.match(/^([^/]+)\/package\.json$/);
      if (match) {
        const prefix = match[1] + "/";

        // Re-normalize all paths with detected prefix
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

        manifest = JSON.parse(content.toString("utf8")) as VsixManifest;
        break;
      }
    }
  }

  if (!manifest) {
    throw new Error("Invalid VSIX: missing package.json");
  }

  return {
    manifest,
    files,
    basePath: vsixPath,
  };
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
