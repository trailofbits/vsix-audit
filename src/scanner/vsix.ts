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

function getZipEntryName(entry: yauzl.Entry): string {
  const fileName = (entry as yauzl.Entry & { fileName: string | Buffer }).fileName;
  return Buffer.isBuffer(fileName) ? fileName.toString("utf8") : fileName;
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

    if (files.has(ref.path)) {
      continue;
    }

    const skipped = archiveWarnings.find((warning) => warning.normalizedPath === ref.path);
    warnings.push(
      makeArchiveWarning(
        skipped ? "ARCHIVE_REFERENCED_FILE_SKIPPED" : "ARCHIVE_REFERENCED_FILE_MISSING",
        skipped ? "Manifest-referenced file was skipped" : "Manifest-referenced file is missing",
        ref.path,
        skipped
          ? `manifest ${ref.kind} reference points to an entry skipped during extraction`
          : `manifest ${ref.kind} reference does not exist in the archive`,
        ref.kind === "main" || ref.kind === "browser" ? "critical" : "high",
        ref.path,
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
