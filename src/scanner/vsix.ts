import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";
import type { VsixContents, VsixManifest } from "./types.js";

const VSIX_EXTENSION_PREFIX = "extension/";
const LOCAL_FILE_HEADER = 0x04034b50;
const CENTRAL_DIR_HEADER = 0x02014b50;

interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  dataOffset: number;
}

function parseZipEntries(buffer: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = [];
  let offset = 0;

  while (offset < buffer.length - 4) {
    const signature = buffer.readUInt32LE(offset);

    if (signature === LOCAL_FILE_HEADER) {
      const compressionMethod = buffer.readUInt16LE(offset + 8);
      const compressedSize = buffer.readUInt32LE(offset + 18);
      const uncompressedSize = buffer.readUInt32LE(offset + 22);
      const fileNameLength = buffer.readUInt16LE(offset + 26);
      const extraFieldLength = buffer.readUInt16LE(offset + 28);
      const fileName = buffer.toString("utf8", offset + 30, offset + 30 + fileNameLength);
      const dataOffset = offset + 30 + fileNameLength + extraFieldLength;

      if (!fileName.endsWith("/")) {
        entries.push({
          name: fileName,
          compressedSize,
          uncompressedSize,
          compressionMethod,
          dataOffset,
        });
      }

      offset = dataOffset + compressedSize;
    } else if (signature === CENTRAL_DIR_HEADER) {
      break;
    } else {
      offset++;
    }
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
