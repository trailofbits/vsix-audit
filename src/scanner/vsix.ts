import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import * as yauzl from "yauzl";
import type {
  ArchiveWarning,
  ArtifactEntry,
  Severity,
  VsixContents,
  VsixManifest,
} from "./types.js";

const VSIX_EXTENSION_PREFIX = "extension/";

/** Maximum uncompressed size for a single entry (500 MB). */
export const MAX_ENTRY_SIZE = 500 * 1024 * 1024;

/** Maximum total extracted size across all entries (1 GB). */
export const MAX_TOTAL_SIZE = 1024 * 1024 * 1024;

/** Maximum compression ratio before flagging as suspicious. */
export const MAX_COMPRESSION_RATIO = 100;

const ZIP_UTF8_FLAG = 0x0800;
const INFO_ZIP_UNICODE_PATH_EXTRA_FIELD = 0x7075;

const CP437_CODE_POINTS = [
  0x0000, 0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25d8, 0x25cb, 0x25d9, 0x2642,
  0x2640, 0x266a, 0x266b, 0x263c, 0x25ba, 0x25c4, 0x2195, 0x203c, 0x00b6, 0x00a7, 0x25ac, 0x21a8,
  0x2191, 0x2193, 0x2192, 0x2190, 0x221f, 0x2194, 0x25b2, 0x25bc, 0x0020, 0x0021, 0x0022, 0x0023,
  0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f,
  0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b,
  0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
  0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050, 0x0051, 0x0052, 0x0053,
  0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f,
  0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006a, 0x006b,
  0x006c, 0x006d, 0x006e, 0x006f, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
  0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x2302, 0x00c7, 0x00fc, 0x00e9, 0x00e2,
  0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
  0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9, 0x00ff, 0x00d6, 0x00dc, 0x00a2,
  0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
  0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb, 0x2591, 0x2592, 0x2593, 0x2502,
  0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510,
  0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566,
  0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b,
  0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580, 0x03b1, 0x00df, 0x0393, 0x03c0,
  0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229,
  0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248, 0x00b0, 0x2219, 0x00b7, 0x221a,
  0x207f, 0x00b2, 0x25a0, 0x00a0,
] as const;

function makeArchiveWarning(
  id: string,
  title: string,
  entryName: string,
  reason: string,
  severity: Severity,
  normalizedPath?: string,
): ArchiveWarning {
  const pathText = normalizedPath ? ` (${normalizedPath})` : "";
  const warning: ArchiveWarning = {
    id,
    title,
    entryName,
    reason,
    severity,
    message: `${title}: ${entryName}${pathText}: ${reason}`,
  };
  if (normalizedPath !== undefined) {
    warning.normalizedPath = normalizedPath;
  }
  return warning;
}

function normalizeZipEntryPath(entryName: string): { path: string } | { reason: string } {
  if (entryName.length === 0) {
    return { reason: "empty ZIP entry path" };
  }
  if (entryName.includes("\0")) {
    return { reason: "NUL byte in ZIP entry path" };
  }
  if (entryName.includes("\\")) {
    return { reason: "backslash in ZIP entry path" };
  }
  if (entryName.startsWith("/")) {
    return { reason: "absolute ZIP entry path" };
  }
  if (/^[A-Za-z]:/.test(entryName)) {
    return { reason: "drive-letter ZIP entry path" };
  }

  const segments = entryName.split("/").filter((part) => part !== "" && part !== ".");
  if (segments.length === 0) {
    return { reason: "empty ZIP entry path after normalization" };
  }
  for (const segment of segments) {
    if (segment === ".." || segment.startsWith("..")) {
      return { reason: "path traversal segment in ZIP entry path" };
    }
  }

  return { path: segments.join("/") };
}

function toExtensionRelativePath(path: string): string {
  return path.startsWith(VSIX_EXTENSION_PREFIX) ? path.slice(VSIX_EXTENSION_PREFIX.length) : path;
}

function portablePathCollisionKey(path: string): string {
  return path.normalize("NFC").toLowerCase();
}

function openZipFile(vsixPath: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(
      vsixPath,
      {
        autoClose: false,
        lazyEntries: true,
        decodeStrings: false,
        strictFileNames: false,
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

function crc32Unsigned(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function decodeCp437(buffer: Buffer): string {
  let result = "";
  for (const byte of buffer) {
    result += String.fromCodePoint(CP437_CODE_POINTS[byte] ?? 0xfffd);
  }
  return result;
}

function getRawZipEntryName(entry: yauzl.Entry): Buffer {
  const rawEntry = entry as yauzl.Entry & { fileName: string | Buffer; fileNameRaw?: Buffer };
  if (rawEntry.fileNameRaw) {
    return rawEntry.fileNameRaw;
  }
  return Buffer.isBuffer(rawEntry.fileName)
    ? rawEntry.fileName
    : Buffer.from(rawEntry.fileName, "utf8");
}

function getUnicodePathExtraFieldName(entry: yauzl.Entry, rawFileName: Buffer): string | undefined {
  for (const extraField of entry.extraFields) {
    if (extraField.id !== INFO_ZIP_UNICODE_PATH_EXTRA_FIELD) {
      continue;
    }
    if (extraField.data.length < 6 || extraField.data.readUInt8(0) !== 1) {
      continue;
    }
    if (extraField.data.readUInt32LE(1) !== crc32Unsigned(rawFileName)) {
      continue;
    }
    return extraField.data.subarray(5).toString("utf8");
  }
  return undefined;
}

function getZipEntryName(entry: yauzl.Entry): string {
  const rawFileName = getRawZipEntryName(entry);
  const unicodeName = getUnicodePathExtraFieldName(entry, rawFileName);
  if (unicodeName !== undefined) {
    return unicodeName;
  }
  if ((entry.generalPurposeBitFlag & ZIP_UTF8_FLAG) !== 0) {
    return rawFileName.toString("utf8");
  }
  return decodeCp437(rawFileName);
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
        reject(new Error(`Failed to read ZIP entry "${getZipEntryName(entry)}"`));
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
      throw new Error(`ZIP entry "${getZipEntryName(entry)}" exceeds ${MAX_ENTRY_SIZE} byte limit`);
    }
    chunks.push(data);
  }

  return Buffer.concat(chunks);
}

export async function extractVsix(vsixPath: string): Promise<VsixContents> {
  const zipFile = await openZipFile(vsixPath);
  const files = new Map<string, Buffer>();
  const archiveWarnings: ArchiveWarning[] = [];
  const artifacts: ArtifactEntry[] = [];

  let manifest: VsixManifest | undefined;
  let totalExtractedSize = 0;
  const portablePathKeys = new Map<string, string>();

  try {
    const entries = await collectZipEntries(zipFile);

    for (const entry of entries) {
      const entryName = getZipEntryName(entry);

      if (entryName.endsWith("/")) {
        continue;
      }

      const normalizedEntry = normalizeZipEntryPath(entryName);
      if ("reason" in normalizedEntry) {
        artifacts.push({
          originalPath: entryName,
          size: 0,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
          skipped: true,
          skipReason: normalizedEntry.reason,
        });
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_INVALID_PATH",
            "Invalid ZIP entry path",
            entryName,
            normalizedEntry.reason,
            "high",
          ),
        );
        continue;
      }

      const relativePath = toExtensionRelativePath(normalizedEntry.path);
      const portablePathKey = portablePathCollisionKey(relativePath);
      const portablePathMatch = portablePathKeys.get(portablePathKey);
      if (portablePathMatch && portablePathMatch !== relativePath) {
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_PORTABLE_PATH_COLLISION",
            "Portable filesystem path collision",
            entryName,
            `entry collides with "${portablePathMatch}" after Unicode/case normalization`,
            "high",
            relativePath,
          ),
        );
      } else {
        portablePathKeys.set(portablePathKey, relativePath);
      }

      if (entry.uncompressedSize > MAX_ENTRY_SIZE) {
        const reason = `declared size ${entry.uncompressedSize} exceeds ${MAX_ENTRY_SIZE} byte limit`;
        artifacts.push({
          originalPath: entryName,
          path: relativePath,
          size: 0,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
          skipped: true,
          skipReason: reason,
        });
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_SKIPPED_ENTRY",
            "Skipped ZIP entry",
            entryName,
            reason,
            "high",
            relativePath,
          ),
        );
        continue;
      }

      if (
        entry.compressedSize > 0 &&
        entry.uncompressedSize / entry.compressedSize > MAX_COMPRESSION_RATIO
      ) {
        const reason =
          `compression ratio ${Math.round(entry.uncompressedSize / entry.compressedSize)}:1 ` +
          `exceeds ${MAX_COMPRESSION_RATIO}:1 limit`;
        artifacts.push({
          originalPath: entryName,
          path: relativePath,
          size: 0,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
          skipped: true,
          skipReason: reason,
        });
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_SKIPPED_ENTRY",
            "Skipped ZIP entry",
            entryName,
            reason,
            "high",
            relativePath,
          ),
        );
        continue;
      }

      if (totalExtractedSize + entry.uncompressedSize > MAX_TOTAL_SIZE) {
        const reason = `total extracted size would exceed ${MAX_TOTAL_SIZE} byte limit`;
        artifacts.push({
          originalPath: entryName,
          path: relativePath,
          size: 0,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
          skipped: true,
          skipReason: reason,
        });
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_SKIPPED_ENTRY",
            "Skipped ZIP entry",
            entryName,
            reason,
            "high",
            relativePath,
          ),
        );
        continue;
      }

      totalExtractedSize += entry.uncompressedSize;
      let content: Buffer;
      try {
        content = await readZipEntry(entry, zipFile);
      } catch (error) {
        const reason = `failed to extract entry (${error instanceof Error ? error.message : String(error)})`;
        artifacts.push({
          originalPath: entryName,
          path: relativePath,
          size: 0,
          compressedSize: entry.compressedSize,
          uncompressedSize: entry.uncompressedSize,
          skipped: true,
          skipReason: reason,
        });
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_SKIPPED_ENTRY",
            "Skipped ZIP entry",
            entryName,
            reason,
            "high",
            relativePath,
          ),
        );
        continue;
      }

      const sha256 = computeSha256(content);
      if (files.has(relativePath)) {
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_DUPLICATE_PATH",
            "Duplicate normalized ZIP path",
            entryName,
            "multiple ZIP entries normalize to the same extension path; the last entry is used",
            "high",
            relativePath,
          ),
        );
      }

      artifacts.push({
        originalPath: entryName,
        path: relativePath,
        size: content.length,
        compressedSize: entry.compressedSize,
        uncompressedSize: entry.uncompressedSize,
        sha256,
        skipped: false,
      });
      files.set(relativePath, content);

      if (relativePath === "package.json") {
        manifest = JSON.parse(content.toString("utf8")) as VsixManifest;
      }
    }
  } finally {
    zipFile.close();
  }

  if (!manifest) {
    manifest = findManifestWithNonStandardPrefix(files, artifacts, archiveWarnings);
  }

  if (!manifest) {
    throw new Error("Invalid VSIX: missing package.json");
  }

  archiveWarnings.push(...findManifestReferenceWarnings(manifest, files, archiveWarnings));
  const warnings = archiveWarnings.map((warning) => warning.message);

  return {
    manifest,
    files,
    basePath: vsixPath,
    artifacts,
    ...(archiveWarnings.length > 0 ? { archiveWarnings } : {}),
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}

/**
 * Find package.json under a non-standard prefix
 * (e.g. "publisher.name-version/" instead of "extension/")
 * and re-normalize all paths.
 */
function findManifestWithNonStandardPrefix(
  files: Map<string, Buffer>,
  artifacts: ArtifactEntry[],
  archiveWarnings: ArchiveWarning[],
): VsixManifest | undefined {
  for (const [path, content] of files) {
    const match = path.match(/^([^/]+)\/package\.json$/);
    if (!match) {
      continue;
    }

    const prefix = match[1] + "/";
    const normalized = new Map<string, Buffer>();

    for (const [p, c] of files) {
      const normalizedPath = p.startsWith(prefix) ? p.slice(prefix.length) : p;
      if (normalized.has(normalizedPath)) {
        archiveWarnings.push(
          makeArchiveWarning(
            "ARCHIVE_DUPLICATE_PATH",
            "Duplicate normalized ZIP path",
            p,
            "multiple ZIP entries normalize to the same extension path after prefix normalization; the last entry is used",
            "high",
            normalizedPath,
          ),
        );
      }

      normalized.set(normalizedPath, c);
    }

    files.clear();
    for (const [p, c] of normalized) {
      files.set(p, c);
    }

    for (const artifact of artifacts) {
      if (artifact.path?.startsWith(prefix)) {
        artifact.path = artifact.path.slice(prefix.length);
      }
    }
    for (const warning of archiveWarnings) {
      if (warning.normalizedPath?.startsWith(prefix)) {
        warning.normalizedPath = warning.normalizedPath.slice(prefix.length);
      }
    }

    return JSON.parse(content.toString("utf8")) as VsixManifest;
  }

  return undefined;
}

function normalizeManifestReference(reference: string): string | null {
  const withoutFragment = reference.split("#")[0]?.split("?")[0] ?? "";
  const trimmed = withoutFragment.replace(/^\.\//, "");
  const normalized = normalizeZipEntryPath(trimmed);
  if ("reason" in normalized) {
    return null;
  }
  return toExtensionRelativePath(normalized.path);
}

function collectManifestReferences(manifest: VsixManifest): Array<{ path: string; kind: string }> {
  const refs: Array<{ path: string; kind: string }> = [];
  const addRef = (value: unknown, kind: string) => {
    if (typeof value !== "string" || value.length === 0) return;
    const normalized = normalizeManifestReference(value);
    if (normalized) {
      refs.push({ path: normalized, kind });
    } else {
      refs.push({ path: value, kind: `${kind}:invalid` });
    }
  };

  addRef(manifest.main, "main");
  addRef(manifest.browser, "browser");

  for (const theme of manifest.contributes?.themes ?? []) {
    addRef(theme.path, "theme");
  }
  for (const iconTheme of manifest.contributes?.iconThemes ?? []) {
    addRef(iconTheme.path, "iconTheme");
  }

  return refs;
}

const NODE_ENTRYPOINT_EXTENSIONS = [".js", ".json", ".node"] as const;

function isCodeEntrypoint(kind: string): boolean {
  return kind === "main" || kind === "browser";
}

function manifestReferenceCandidates(ref: { path: string; kind: string }): string[] {
  const candidates = [ref.path];

  if (isCodeEntrypoint(ref.kind)) {
    for (const extension of NODE_ENTRYPOINT_EXTENSIONS) {
      candidates.push(`${ref.path}${extension}`);
    }
    for (const extension of NODE_ENTRYPOINT_EXTENSIONS) {
      candidates.push(`${ref.path}/index${extension}`);
    }
  }

  return [...new Set(candidates)];
}

function findManifestReferenceResolution(
  ref: { path: string; kind: string },
  files: Map<string, Buffer>,
  archiveWarnings: ArchiveWarning[],
): { found: true } | { skipped: ArchiveWarning; path: string } | null {
  for (const candidate of manifestReferenceCandidates(ref)) {
    if (files.has(candidate)) {
      return { found: true };
    }

    const skipped = archiveWarnings.find((warning) => warning.normalizedPath === candidate);
    if (skipped) {
      return { skipped, path: candidate };
    }
  }

  return null;
}

function findManifestReferenceWarnings(
  manifest: VsixManifest,
  files: Map<string, Buffer>,
  archiveWarnings: ArchiveWarning[],
): ArchiveWarning[] {
  const warnings: ArchiveWarning[] = [];

  for (const ref of collectManifestReferences(manifest)) {
    if (ref.kind.endsWith(":invalid")) {
      warnings.push(
        makeArchiveWarning(
          "ARCHIVE_INVALID_MANIFEST_REFERENCE",
          "Invalid manifest file reference",
          ref.path,
          `manifest ${ref.kind.slice(0, -8)} reference is not a safe relative path`,
          "high",
          ref.path,
        ),
      );
      continue;
    }

    const resolution = findManifestReferenceResolution(ref, files, archiveWarnings);
    if (resolution && "found" in resolution) {
      continue;
    }

    const skippedResolution = resolution && "skipped" in resolution ? resolution : undefined;
    const skipped = skippedResolution?.skipped;
    const warningPath = skippedResolution?.path ?? ref.path;
    warnings.push(
      makeArchiveWarning(
        skipped ? "ARCHIVE_REFERENCED_FILE_SKIPPED" : "ARCHIVE_REFERENCED_FILE_MISSING",
        skipped ? "Manifest-referenced file was skipped" : "Manifest-referenced file is missing",
        warningPath,
        skipped
          ? `manifest ${ref.kind} reference points to an entry skipped during extraction`
          : `manifest ${ref.kind} reference does not exist in the archive`,
        ref.kind === "main" || ref.kind === "browser" ? "critical" : "high",
        warningPath,
      ),
    );
  }

  return warnings;
}

export async function loadDirectory(dirPath: string): Promise<VsixContents> {
  const files = new Map<string, Buffer>();
  const artifacts: ArtifactEntry[] = [];

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
        artifacts.push({
          originalPath: relativePath,
          path: relativePath,
          size: content.length,
          sha256: computeSha256(content),
          skipped: false,
        });
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
    artifacts,
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
