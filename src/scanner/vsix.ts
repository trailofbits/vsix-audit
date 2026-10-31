import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import * as yauzl from "yauzl";
import { parseManifest } from "#internal/scanner/manifest.js";
import type {
  ArchiveWarning,
  ArtifactEntry,
  VsixContents,
  VsixManifest,
} from "#internal/scanner/types.js";

const VSIX_EXTENSION_PREFIX = "extension/";

/** Maximum uncompressed size for a single entry (500 MB). */
export const MAX_ENTRY_SIZE = 500 * 1024 * 1024;

/** Maximum total extracted size across all entries (1 GB). */
export const MAX_TOTAL_SIZE = 1024 * 1024 * 1024;

/** Maximum compression ratio before flagging as suspicious. */
export const MAX_COMPRESSION_RATIO = 100;

function makeArchiveWarning(warning: Omit<ArchiveWarning, "message">): ArchiveWarning {
  const path =
    warning.normalizedPath !== undefined && warning.normalizedPath !== ""
      ? ` (${warning.normalizedPath})`
      : "";
  return {
    ...warning,
    message: `${warning.title}: ${warning.entryName}${path}: ${warning.reason}`,
  };
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
        resolve(zipFile);
      },
    );
  });
}

function getZipEntryName(entry: yauzl.Entry): string {
  return yauzl.getFileNameLowLevel(
    entry.generalPurposeBitFlag,
    entry.fileNameRaw,
    entry.extraFields,
    true,
  );
}

function collectZipEntries(zipFile: yauzl.ZipFile): Promise<yauzl.Entry[]> {
  return new Promise((resolve, reject) => {
    const entries: yauzl.Entry[] = [];

    zipFile.once("error", reject);
    zipFile.on("entry", (entry: yauzl.Entry) => {
      entries.push(entry);
      zipFile.readEntry();
    });
    zipFile.once("end", () => {
      resolve(entries);
    });
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
      resolve(stream);
    });
  });
}

async function readStream(
  stream: NodeJS.ReadableStream,
  limit: number,
  input: string,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let actualSize = 0;
  for await (const chunk of stream) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    actualSize += data.length;
    if (actualSize > limit)
      throw new Error(
        `Cannot read ${input}: exceeds ${limit} byte limit. Inspect the input manually.`,
      );
    chunks.push(data);
  }
  return Buffer.concat(chunks);
}

interface ArchiveContents {
  files: Map<string, Buffer>;
  artifacts: ArtifactEntry[];
  warnings: ArchiveWarning[];
  paths: Map<string, string>;
  totalSize: number;
}

function skipArchiveEntry(
  state: ArchiveContents,
  entry: yauzl.Entry,
  warning: ArchiveWarning,
): void {
  state.artifacts.push({
    originalPath: warning.entryName,
    size: 0,
    ...(warning.normalizedPath === undefined ? {} : { path: warning.normalizedPath }),
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize,
    skipped: true,
    skipReason: warning.reason,
  });
  state.warnings.push(warning);
}

function archiveSizeError(entry: yauzl.Entry, totalSize: number): string | undefined {
  const sizeError = directorySkipReason(true, entry.uncompressedSize, totalSize);
  if (entry.uncompressedSize > MAX_ENTRY_SIZE) return sizeError;
  if (
    entry.compressedSize > 0 &&
    entry.uncompressedSize / entry.compressedSize > MAX_COMPRESSION_RATIO
  ) {
    return `compression ratio ${Math.round(entry.uncompressedSize / entry.compressedSize)}:1 exceeds ${MAX_COMPRESSION_RATIO}:1 limit`;
  }
  return sizeError;
}

function recordPathCollisions(state: ArchiveContents, name: string, path: string): void {
  const key = portablePathCollisionKey(path);
  const previous = state.paths.get(key);
  if (previous !== undefined && previous !== path) {
    state.warnings.push(
      makeArchiveWarning({
        id: "ARCHIVE_PORTABLE_PATH_COLLISION",
        title: "Portable filesystem path collision",
        entryName: name,
        normalizedPath: path,
        reason: `entry collides with "${previous}" after Unicode/case normalization`,
        severity: "high",
      }),
    );
  } else state.paths.set(key, path);
  if (state.files.has(path)) {
    state.warnings.push(
      makeArchiveWarning({
        id: "ARCHIVE_DUPLICATE_PATH",
        title: "Duplicate normalized ZIP path",
        entryName: name,
        normalizedPath: path,
        reason: "multiple ZIP entries normalize to the same extension path; the last entry is used",
        severity: "high",
      }),
    );
  }
}

async function readArchiveEntry(
  entry: yauzl.Entry,
  zip: yauzl.ZipFile,
  state: ArchiveContents,
): Promise<void> {
  const name = getZipEntryName(entry);
  if (name.endsWith("/")) return;
  const normalized = normalizeZipEntryPath(name);
  if ("reason" in normalized) {
    skipArchiveEntry(
      state,
      entry,
      makeArchiveWarning({
        id: "ARCHIVE_INVALID_PATH",
        title: "Invalid ZIP entry path",
        entryName: name,
        reason: normalized.reason,
        severity: "high",
      }),
    );
    return;
  }
  const path = toExtensionRelativePath(normalized.path);
  recordPathCollisions(state, name, path);
  const sizeError = archiveSizeError(entry, state.totalSize);
  if (sizeError !== undefined) {
    skipArchiveEntry(
      state,
      entry,
      makeArchiveWarning({
        id: "ARCHIVE_SKIPPED_ENTRY",
        title: "Skipped ZIP entry",
        entryName: name,
        reason: sizeError,
        severity: "high",
        normalizedPath: path,
      }),
    );
    return;
  }
  const remainingBudget = MAX_TOTAL_SIZE - state.totalSize;
  state.totalSize += entry.uncompressedSize;
  try {
    const stream = await openZipEntryStream(zip, entry);
    const content = await readStream(
      stream,
      Math.min(entry.uncompressedSize, MAX_ENTRY_SIZE, remainingBudget),
      name,
    );
    if (content.length !== entry.uncompressedSize)
      throw new Error("uncompressed size does not match ZIP metadata");
    state.files.set(path, content);
    state.artifacts.push({
      originalPath: name,
      path,
      size: content.length,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      sha256: computeSha256(content),
      skipped: false,
    });
  } catch (error) {
    skipArchiveEntry(
      state,
      entry,
      makeArchiveWarning({
        id: "ARCHIVE_SKIPPED_ENTRY",
        title: "Skipped ZIP entry",
        entryName: name,
        reason: `failed to extract entry (${error instanceof Error ? error.message : String(error)})`,
        severity: "high",
        normalizedPath: path,
      }),
    );
  }
}

/** Read a VSIX archive without executing its contents and report every skipped entry. */
export async function extractVsix(vsixPath: string): Promise<VsixContents> {
  const zip = await openZipFile(vsixPath);
  const state: ArchiveContents = {
    files: new Map(),
    artifacts: [],
    warnings: [],
    paths: new Map(),
    totalSize: 0,
  };
  try {
    for (const entry of await collectZipEntries(zip)) await readArchiveEntry(entry, zip, state);
  } finally {
    zip.close();
  }
  if (!state.files.has("package.json"))
    normalizeNonStandardPrefix(state.files, state.artifacts, state.warnings);
  return finishLoading(vsixPath, state.files, state.artifacts, state.warnings);
}

/**
 * Find package.json under a non-standard prefix
 * (e.g. "publisher.name-version/" instead of "extension/")
 * and re-normalize all paths.
 */
function normalizeNonStandardPrefix(
  files: Map<string, Buffer>,
  artifacts: ArtifactEntry[],
  archiveWarnings: ArchiveWarning[],
): void {
  for (const path of files.keys()) {
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
          makeArchiveWarning({
            id: "ARCHIVE_DUPLICATE_PATH",
            title: "Duplicate normalized ZIP path",
            entryName: p,
            reason:
              "multiple ZIP entries normalize to the same extension path after prefix normalization; the last entry is used",
            severity: "high",
            normalizedPath: normalizedPath,
          }),
        );
      }

      normalized.set(normalizedPath, c);
    }

    files.clear();
    for (const [p, c] of normalized) {
      files.set(p, c);
    }

    normalizeArtifactPaths(prefix, artifacts, archiveWarnings);

    return;
  }
}

function normalizeArtifactPaths(
  prefix: string,
  artifacts: ArtifactEntry[],
  archiveWarnings: ArchiveWarning[],
): void {
  for (const artifact of artifacts) {
    if (artifact.path?.startsWith(prefix) === true) {
      artifact.path = artifact.path.slice(prefix.length);
    }
  }
  for (const warning of archiveWarnings) {
    if (warning.normalizedPath?.startsWith(prefix) === true) {
      warning.normalizedPath = warning.normalizedPath.slice(prefix.length);
    }
  }
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
  const addRef = (value: unknown, kind: string): void => {
    if (typeof value !== "string" || value.length === 0) return;
    const normalized = normalizeManifestReference(value);
    if (normalized !== null && normalized !== "") {
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
        makeArchiveWarning({
          id: "ARCHIVE_INVALID_MANIFEST_REFERENCE",
          title: "Invalid manifest file reference",
          entryName: ref.path,
          reason: `manifest ${ref.kind.slice(0, -8)} reference is not a safe relative path`,
          severity: "high",
          normalizedPath: ref.path,
        }),
      );
      continue;
    }

    const resolution = findManifestReferenceResolution(ref, files, archiveWarnings);
    if (resolution && "found" in resolution) {
      continue;
    }

    const skipped = resolution && "skipped" in resolution ? resolution : undefined;
    warnings.push(unresolvedReferenceWarning(ref, skipped));
  }

  return warnings;
}

function unresolvedReferenceWarning(
  ref: { path: string; kind: string },
  skipped: { path: string; skipped: ArchiveWarning } | undefined,
): ArchiveWarning {
  const problem =
    skipped === undefined
      ? {
          id: "ARCHIVE_REFERENCED_FILE_MISSING",
          title: "Manifest-referenced file is missing",
          path: ref.path,
          reason: `manifest ${ref.kind} reference does not exist in the archive`,
        }
      : {
          id: "ARCHIVE_REFERENCED_FILE_SKIPPED",
          title: "Manifest-referenced file was skipped",
          path: skipped.path,
          reason: `manifest ${ref.kind} reference points to an entry skipped during extraction`,
        };
  return makeArchiveWarning({
    id: problem.id,
    title: problem.title,
    entryName: problem.path,
    reason: problem.reason,
    severity: isCodeEntrypoint(ref.kind) ? "critical" : "high",
    normalizedPath: problem.path,
  });
}

function finishLoading(
  basePath: string,
  files: Map<string, Buffer>,
  artifacts: ArtifactEntry[],
  archiveWarnings: ArchiveWarning[],
): VsixContents {
  const manifestBuffer = files.get("package.json");
  if (!manifestBuffer) throw new Error(`Cannot load ${basePath}: missing package.json.`);
  const manifest = parseManifest(manifestBuffer, `${basePath}/package.json`);
  archiveWarnings.push(...findManifestReferenceWarnings(manifest, files, archiveWarnings));
  return {
    manifest,
    files,
    basePath,
    artifacts,
    ...(archiveWarnings.length > 0 ? { archiveWarnings } : {}),
  };
}

/** Read an installed or extracted extension with the archive size and entry-point checks. */
export async function loadDirectory(dirPath: string): Promise<VsixContents> {
  const files = new Map<string, Buffer>();
  const artifacts: ArtifactEntry[] = [];
  const warnings: ArchiveWarning[] = [];
  let totalSize = 0;

  async function walkDir(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === ".git") continue;
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walkDir(fullPath);
        continue;
      }
      const filename = relative(dirPath, fullPath).split(sep).join("/");
      const size = entry.isFile() ? (await stat(fullPath)).size : 0;
      const reason = directorySkipReason(entry.isFile(), size, totalSize);
      if (reason !== undefined) {
        artifacts.push({
          originalPath: filename,
          path: filename,
          size: 0,
          skipped: true,
          skipReason: reason,
        });
        warnings.push(
          makeArchiveWarning({
            id: "ARCHIVE_SKIPPED_ENTRY",
            title: "Skipped directory entry",
            entryName: filename,
            reason: reason,
            severity: "high",
            normalizedPath: filename,
          }),
        );
        continue;
      }
      totalSize += size;
      const content = await readStream(createReadStream(fullPath), size, fullPath);
      if (content.length !== size) {
        throw new Error(
          `Cannot load ${fullPath}: size changed while reading. Stop the writer and retry.`,
        );
      }
      files.set(filename, content);
      artifacts.push({
        originalPath: filename,
        path: filename,
        size: content.length,
        sha256: computeSha256(content),
        skipped: false,
      });
    }
  }
  await walkDir(dirPath);
  return finishLoading(dirPath, files, artifacts, warnings);
}

function directorySkipReason(isFile: boolean, size: number, totalSize: number): string | undefined {
  if (!isFile) return "symbolic links and special files are not followed";
  if (size > MAX_ENTRY_SIZE) return `declared size ${size} exceeds ${MAX_ENTRY_SIZE} byte limit`;
  if (totalSize + size > MAX_TOTAL_SIZE) {
    return `total extracted size would exceed ${MAX_TOTAL_SIZE} byte limit`;
  }
  return undefined;
}

export async function loadExtension(target: string): Promise<VsixContents> {
  let stats;
  try {
    stats = await stat(target);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Cannot inspect target ${target}: ${reason}. Check that the path exists and is readable.`,
      { cause: error },
    );
  }

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
