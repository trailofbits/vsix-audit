import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import {
  MAX_COMPRESSION_RATIO,
  MAX_ENTRY_SIZE,
  computeSha256,
  extractVsix,
  loadDirectory,
  loadExtension,
} from "./vsix.js";

/**
 * Create a minimal ZIP file buffer for testing.
 * Supports data descriptors (bit 3) which cause local header sizes to be 0.
 */
function createTestZip(
  files: Array<{
    name: string;
    content: string;
    rawName?: Buffer;
    extraFields?: Buffer;
    utf8Name?: boolean;
  }>,
  options: { useDataDescriptor?: boolean } = {},
): Buffer {
  const { useDataDescriptor = false } = options;
  const chunks: Buffer[] = [];
  const centralDirEntries: Buffer[] = [];

  for (const file of files) {
    const localHeaderOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
    const content = Buffer.from(file.content, "utf8");
    const compressed = deflateRawSync(content);
    const fileName = file.rawName ?? Buffer.from(file.name, "utf8");
    const extraFields = file.extraFields ?? Buffer.alloc(0);

    // General purpose bit flag: bit 3 = data descriptor, bit 11 = UTF-8 names.
    const gpBitFlag =
      (useDataDescriptor ? 0x0008 : 0x0000) | (file.utf8Name === false ? 0 : 0x0800);

    // Local file header (30 bytes + filename)
    const localHeader = Buffer.alloc(30 + fileName.length + extraFields.length);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(gpBitFlag, 6); // general purpose bit flag
    localHeader.writeUInt16LE(8, 8); // compression method (deflate)
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0, 12); // mod date
    // CRC and sizes: 0 if data descriptor, actual values otherwise
    if (useDataDescriptor) {
      localHeader.writeUInt32LE(0, 14); // crc32 = 0
      localHeader.writeUInt32LE(0, 18); // compressed size = 0
      localHeader.writeUInt32LE(0, 22); // uncompressed size = 0
    } else {
      localHeader.writeUInt32LE(crc32(content), 14);
      localHeader.writeUInt32LE(compressed.length, 18);
      localHeader.writeUInt32LE(content.length, 22);
    }
    localHeader.writeUInt16LE(fileName.length, 26);
    localHeader.writeUInt16LE(extraFields.length, 28);
    fileName.copy(localHeader, 30);
    extraFields.copy(localHeader, 30 + fileName.length);
    chunks.push(localHeader);

    // Compressed data
    chunks.push(compressed);

    // Data descriptor (if bit 3 set) - 16 bytes with signature
    if (useDataDescriptor) {
      const dataDesc = Buffer.alloc(16);
      dataDesc.writeUInt32LE(0x08074b50, 0); // signature (optional but common)
      dataDesc.writeUInt32LE(crc32(content), 4);
      dataDesc.writeUInt32LE(compressed.length, 8);
      dataDesc.writeUInt32LE(content.length, 12);
      chunks.push(dataDesc);
    }

    // Central directory entry (46 bytes + filename)
    const cdEntry = Buffer.alloc(46 + fileName.length + extraFields.length);
    cdEntry.writeUInt32LE(0x02014b50, 0); // signature
    cdEntry.writeUInt16LE(20, 4); // version made by
    cdEntry.writeUInt16LE(20, 6); // version needed
    cdEntry.writeUInt16LE(gpBitFlag, 8); // general purpose bit flag
    cdEntry.writeUInt16LE(8, 10); // compression method
    cdEntry.writeUInt16LE(0, 12); // mod time
    cdEntry.writeUInt16LE(0, 14); // mod date
    cdEntry.writeUInt32LE(crc32(content), 16); // crc32 (always correct in CD)
    cdEntry.writeUInt32LE(compressed.length, 20); // compressed size (always correct)
    cdEntry.writeUInt32LE(content.length, 24); // uncompressed size (always correct)
    cdEntry.writeUInt16LE(fileName.length, 28);
    cdEntry.writeUInt16LE(extraFields.length, 30);
    cdEntry.writeUInt16LE(0, 32); // comment length
    cdEntry.writeUInt16LE(0, 34); // disk number start
    cdEntry.writeUInt16LE(0, 36); // internal file attributes
    cdEntry.writeUInt32LE(0, 38); // external file attributes
    cdEntry.writeUInt32LE(localHeaderOffset, 42); // relative offset of local header
    fileName.copy(cdEntry, 46);
    extraFields.copy(cdEntry, 46 + fileName.length);
    centralDirEntries.push(cdEntry);
  }

  const cdOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
  const cdSize = centralDirEntries.reduce((sum, buf) => sum + buf.length, 0);

  // Add central directory entries
  chunks.push(...centralDirEntries);

  // End of central directory (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk with CD
  eocd.writeUInt16LE(files.length, 8); // entries on this disk
  eocd.writeUInt16LE(files.length, 10); // total entries
  eocd.writeUInt32LE(cdSize, 12); // size of CD
  eocd.writeUInt32LE(cdOffset, 16); // offset to CD
  eocd.writeUInt16LE(0, 20); // comment length
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

/**
 * Simple CRC32 implementation for test ZIP creation.
 */
function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createUnicodePathExtraField(rawName: Buffer, unicodeName: string): Buffer {
  const unicodeNameBuffer = Buffer.from(unicodeName, "utf8");
  const data = Buffer.alloc(5 + unicodeNameBuffer.length);
  data.writeUInt8(1, 0);
  data.writeUInt32LE(crc32(rawName), 1);
  unicodeNameBuffer.copy(data, 5);

  const field = Buffer.alloc(4 + data.length);
  field.writeUInt16LE(0x7075, 0);
  field.writeUInt16LE(data.length, 2);
  data.copy(field, 4);
  return field;
}

interface SpoofedFile {
  name: string;
  content: string;
  spoofedUncompressedSize?: number;
  spoofedCompressedSize?: number;
}

/**
 * Create a ZIP file with spoofed size fields in the central directory.
 * Used to simulate decompression bombs without actually creating
 * large files.
 */
function createSpoofedZip(files: SpoofedFile[]): Buffer {
  const chunks: Buffer[] = [];
  const centralDirEntries: Buffer[] = [];

  for (const file of files) {
    const localHeaderOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
    const content = Buffer.from(file.content, "utf8");
    const compressed = deflateRawSync(content);
    const fileName = Buffer.from(file.name, "utf8");

    const declaredCompressed = file.spoofedCompressedSize ?? compressed.length;
    const declaredUncompressed = file.spoofedUncompressedSize ?? content.length;

    const localHeader = Buffer.alloc(30 + fileName.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc32(content), 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(content.length, 22);
    localHeader.writeUInt16LE(fileName.length, 26);
    localHeader.writeUInt16LE(0, 28);
    fileName.copy(localHeader, 30);
    chunks.push(localHeader);

    chunks.push(compressed);

    const cdEntry = Buffer.alloc(46 + fileName.length);
    cdEntry.writeUInt32LE(0x02014b50, 0);
    cdEntry.writeUInt16LE(20, 4);
    cdEntry.writeUInt16LE(20, 6);
    cdEntry.writeUInt16LE(0, 8);
    cdEntry.writeUInt16LE(8, 10);
    cdEntry.writeUInt16LE(0, 12);
    cdEntry.writeUInt16LE(0, 14);
    cdEntry.writeUInt32LE(crc32(content), 16);
    cdEntry.writeUInt32LE(declaredCompressed, 20);
    cdEntry.writeUInt32LE(declaredUncompressed, 24);
    cdEntry.writeUInt16LE(fileName.length, 28);
    cdEntry.writeUInt16LE(0, 30);
    cdEntry.writeUInt16LE(0, 32);
    cdEntry.writeUInt16LE(0, 34);
    cdEntry.writeUInt16LE(0, 36);
    cdEntry.writeUInt32LE(0, 38);
    cdEntry.writeUInt32LE(localHeaderOffset, 42);
    fileName.copy(cdEntry, 46);
    centralDirEntries.push(cdEntry);
  }

  const cdOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
  const cdSize = centralDirEntries.reduce((sum, buf) => sum + buf.length, 0);

  chunks.push(...centralDirEntries);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

describe("computeSha256", () => {
  it("computes correct hash for buffer", () => {
    const content = Buffer.from("test content");
    const hash = computeSha256(content);

    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(hash).toBe("6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72");
  });

  it("returns different hashes for different content", () => {
    const hash1 = computeSha256(Buffer.from("content1"));
    const hash2 = computeSha256(Buffer.from("content2"));

    expect(hash1).not.toBe(hash2);
  });
});

describe("loadDirectory", () => {
  const testDir = join(tmpdir(), `vsix-audit-test-${Date.now()}`);

  beforeAll(async () => {
    await mkdir(testDir, { recursive: true });
    await mkdir(join(testDir, "src"), { recursive: true });

    const manifest = {
      name: "test-extension",
      publisher: "test-publisher",
      version: "1.0.0",
      main: "./src/extension.js",
      activationEvents: ["onCommand:test.command"],
    };

    await writeFile(join(testDir, "package.json"), JSON.stringify(manifest, null, 2));
    await writeFile(join(testDir, "src", "extension.js"), 'console.log("hello");');
    await writeFile(join(testDir, "README.md"), "# Test Extension");
  });

  afterAll(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it("loads extension from directory", async () => {
    const contents = await loadDirectory(testDir);

    expect(contents.manifest.name).toBe("test-extension");
    expect(contents.manifest.publisher).toBe("test-publisher");
    expect(contents.manifest.version).toBe("1.0.0");
    expect(contents.basePath).toBe(testDir);
  });

  it("loads all files from directory", async () => {
    const contents = await loadDirectory(testDir);

    expect(contents.files.has("package.json")).toBe(true);
    expect(contents.files.has("src/extension.js")).toBe(true);
    expect(contents.files.has("README.md")).toBe(true);
  });

  it("excludes node_modules and .git directories", async () => {
    // Create node_modules and .git directories
    await mkdir(join(testDir, "node_modules", "dep"), { recursive: true });
    await mkdir(join(testDir, ".git", "objects"), { recursive: true });
    await writeFile(join(testDir, "node_modules", "dep", "index.js"), "module.exports = {};");
    await writeFile(join(testDir, ".git", "objects", "abc"), "git object");

    const contents = await loadDirectory(testDir);

    // Should not include node_modules or .git files
    expect([...contents.files.keys()].some((f) => f.includes("node_modules"))).toBe(false);
    expect([...contents.files.keys()].some((f) => f.includes(".git"))).toBe(false);
  });

  it("throws error for directory without package.json", async () => {
    const emptyDir = join(tmpdir(), `vsix-audit-empty-${Date.now()}`);
    await mkdir(emptyDir, { recursive: true });

    try {
      await expect(loadDirectory(emptyDir)).rejects.toThrow("missing package.json");
    } finally {
      await rm(emptyDir, { recursive: true, force: true });
    }
  });
});

describe("loadExtension", () => {
  const testDir = join(tmpdir(), `vsix-audit-load-test-${Date.now()}`);

  beforeAll(async () => {
    await mkdir(testDir, { recursive: true });
    const manifest = {
      name: "load-test",
      publisher: "test",
      version: "2.0.0",
    };
    await writeFile(join(testDir, "package.json"), JSON.stringify(manifest));
  });

  afterAll(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  it("loads directory when target is a directory", async () => {
    const contents = await loadExtension(testDir);

    expect(contents.manifest.name).toBe("load-test");
    expect(contents.manifest.version).toBe("2.0.0");
  });

  it("throws error for unsupported file type", async () => {
    const invalidFile = join(tmpdir(), "invalid.txt");
    await writeFile(invalidFile, "not a vsix");

    try {
      await expect(loadExtension(invalidFile)).rejects.toThrow("Unsupported target");
    } finally {
      await rm(invalidFile, { force: true });
    }
  });
});

describe("extractVsix", () => {
  it("extracts standard ZIP without data descriptors", async () => {
    const manifest = JSON.stringify({
      name: "test-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/main.js", content: 'console.log("hello");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-standard-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.manifest.name).toBe("test-ext");
      expect(contents.manifest.version).toBe("1.0.0");
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("main.js")).toBe(true);
      expect(contents.files.get("main.js")?.toString()).toBe('console.log("hello");');
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("extracts ZIP with data descriptors (bit 3 set)", async () => {
    const manifest = JSON.stringify({
      name: "data-desc-ext",
      publisher: "test",
      version: "2.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/src/index.js", content: "export default function() {}" },
      ],
      { useDataDescriptor: true },
    );

    const vsixPath = join(tmpdir(), `test-datadesc-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.manifest.name).toBe("data-desc-ext");
      expect(contents.manifest.version).toBe("2.0.0");
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("src/index.js")).toBe(true);
      expect(contents.files.get("src/index.js")?.toString()).toBe("export default function() {}");
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("handles large files with data descriptors", async () => {
    const manifest = JSON.stringify({
      name: "large-file-ext",
      publisher: "test",
      version: "3.0.0",
    });

    // Use pseudo-random content to stay under compression ratio limit
    let seed = 12345;
    const chars: string[] = [];
    for (let i = 0; i < 20000; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      chars.push(String.fromCharCode(33 + (seed % 94)));
    }
    const largeContent = chars.join("");

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/large.txt", content: largeContent },
      ],
      { useDataDescriptor: true },
    );

    const vsixPath = join(tmpdir(), `test-large-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.manifest.name).toBe("large-file-ext");
      expect(contents.files.has("large.txt")).toBe(true);
      expect(contents.files.get("large.txt")?.toString()).toBe(largeContent);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("uses the last duplicate entry for the same normalized path", async () => {
    const manifest = JSON.stringify({
      name: "duplicate-entry-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/main.js", content: 'console.log("first");' },
        { name: "extension/main.js", content: 'console.log("second");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-duplicate-entry-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.get("main.js")?.toString()).toBe('console.log("second");');
      expect(contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_DUPLICATE_PATH")).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when dot segments create a duplicate normalized path", async () => {
    const manifest = JSON.stringify({
      name: "dot-segment-duplicate-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/./main.js", content: 'console.log("first");' },
        { name: "extension/main.js", content: 'console.log("second");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-dot-duplicate-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.get("main.js")?.toString()).toBe('console.log("second");');
      expect(contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_DUPLICATE_PATH")).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns and skips unsafe ZIP entry paths", async () => {
    const manifest = JSON.stringify({
      name: "unsafe-path-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/../evil.js", content: "traversal" },
        { name: "/extension/absolute.js", content: "absolute" },
        { name: "extension\\backslash.js", content: "backslash" },
        { name: "C:/extension/drive.js", content: "drive" },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-unsafe-paths-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);
      const invalidWarnings = contents.archiveWarnings?.filter(
        (warning) => warning.id === "ARCHIVE_INVALID_PATH",
      );

      expect(contents.files.has("evil.js")).toBe(false);
      expect(contents.files.has("absolute.js")).toBe(false);
      expect(contents.files.has("extension\\backslash.js")).toBe(false);
      expect(contents.files.has("drive.js")).toBe(false);
      expect(invalidWarnings).toHaveLength(4);
      expect(invalidWarnings?.map((warning) => warning.reason)).toEqual(
        expect.arrayContaining([
          "path traversal segment in ZIP entry path",
          "absolute ZIP entry path",
          "backslash in ZIP entry path",
          "drive-letter ZIP entry path",
        ]),
      );
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when manifest main points to a missing file", async () => {
    const manifest = JSON.stringify({
      name: "missing-main-ext",
      publisher: "test",
      version: "1.0.0",
      main: "main.js",
    });

    const zipBuffer = createTestZip([{ name: "extension/package.json", content: manifest }], {
      useDataDescriptor: false,
    });

    const vsixPath = join(tmpdir(), `test-missing-main-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(
        contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_REFERENCED_FILE_MISSING"),
      ).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when manifest main points to a skipped ZIP entry", async () => {
    const manifest = JSON.stringify({
      name: "skipped-main-ext",
      publisher: "test",
      version: "1.0.0",
      main: "main.js",
    });

    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/main.js",
        content: "small",
        spoofedUncompressedSize: MAX_ENTRY_SIZE + 1,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-skipped-main-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("main.js")).toBe(false);
      expect(contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_SKIPPED_ENTRY")).toBe(true);
      expect(
        contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_REFERENCED_FILE_SKIPPED"),
      ).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when paths collide on case-insensitive filesystems", async () => {
    const manifest = JSON.stringify({
      name: "case-collision-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/Main.js", content: 'console.log("upper");' },
        { name: "extension/main.js", content: 'console.log("lower");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-case-collision-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);
      const collision = contents.archiveWarnings?.find(
        (warning) => warning.id === "ARCHIVE_PORTABLE_PATH_COLLISION",
      );

      expect(contents.files.has("Main.js")).toBe(true);
      expect(contents.files.has("main.js")).toBe(true);
      expect(collision?.normalizedPath).toBe("main.js");
      expect(collision?.reason).toContain("Main.js");
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when paths collide after Unicode normalization", async () => {
    const manifest = JSON.stringify({
      name: "unicode-collision-ext",
      publisher: "test",
      version: "1.0.0",
    });
    const decomposed = "cafe\u0301.js";
    const composed = "caf\u00e9.js";

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: `extension/${decomposed}`, content: 'console.log("decomposed");' },
        { name: `extension/${composed}`, content: 'console.log("composed");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-unicode-collision-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);
      const collision = contents.archiveWarnings?.find(
        (warning) => warning.id === "ARCHIVE_PORTABLE_PATH_COLLISION",
      );

      expect(contents.files.has(decomposed)).toBe(true);
      expect(contents.files.has(composed)).toBe(true);
      expect(collision?.normalizedPath).toBe(composed);
      expect(collision?.reason).toContain(decomposed);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("decodes non-UTF-8 ZIP entry names as CP437", async () => {
    const manifest = JSON.stringify({
      name: "cp437-name-ext",
      publisher: "test",
      version: "1.0.0",
    });
    const rawName = Buffer.concat([
      Buffer.from("extension/caf", "ascii"),
      Buffer.from([0x82]),
      Buffer.from(".js", "ascii"),
    ]);

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        {
          name: "extension/caf-e.js",
          rawName,
          utf8Name: false,
          content: 'console.log("cp437");',
        },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-cp437-name-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("caf\u00e9.js")).toBe(true);
      expect(contents.files.get("caf\u00e9.js")?.toString()).toBe('console.log("cp437");');
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("prefers Info-ZIP Unicode Path extra fields when present", async () => {
    const manifest = JSON.stringify({
      name: "unicode-path-extra-field-ext",
      publisher: "test",
      version: "1.0.0",
    });
    const rawName = Buffer.from("extension/fallback.js", "ascii");
    const unicodeName = "extension/unicode-\u2603.js";
    const extraFields = createUnicodePathExtraField(rawName, unicodeName);

    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        {
          name: "extension/fallback.js",
          rawName,
          extraFields,
          utf8Name: false,
          content: 'console.log("unicode path");',
        },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-unicode-path-extra-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("unicode-\u2603.js")).toBe(true);
      expect(contents.files.has("fallback.js")).toBe(false);
      expect(contents.files.get("unicode-\u2603.js")?.toString()).toBe(
        'console.log("unicode path");',
      );
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("throws on invalid ZIP without EOCD", async () => {
    const invalidZip = Buffer.from("not a valid zip file");
    const vsixPath = join(tmpdir(), `test-invalid-${Date.now()}.vsix`);
    await writeFile(vsixPath, invalidZip);

    try {
      await expect(extractVsix(vsixPath)).rejects.toThrow(
        "End of central directory record signature not found",
      );
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("throws on ZIP missing package.json", async () => {
    const zipBuffer = createTestZip([{ name: "extension/readme.md", content: "# Hello" }], {
      useDataDescriptor: false,
    });

    const vsixPath = join(tmpdir(), `test-nomanifest-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      await expect(extractVsix(vsixPath)).rejects.toThrow("missing package.json");
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("extracts ZIP with non-standard prefix (not extension/)", async () => {
    const manifest = JSON.stringify({
      name: "weird-prefix-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "weird-prefix-ext-1.0.0/package.json", content: manifest },
        { name: "weird-prefix-ext-1.0.0/main.js", content: 'console.log("hello");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-weird-prefix-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.manifest.name).toBe("weird-prefix-ext");
      expect(contents.manifest.version).toBe("1.0.0");
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("main.js")).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("warns when non-standard prefix normalization creates a duplicate path", async () => {
    const manifest = JSON.stringify({
      name: "weird-prefix-duplicate-ext",
      publisher: "test",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        { name: "weird-prefix-duplicate-ext-1.0.0/package.json", content: manifest },
        { name: "weird-prefix-duplicate-ext-1.0.0/main.js", content: 'console.log("first");' },
        { name: "main.js", content: 'console.log("second");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-weird-prefix-duplicate-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.get("main.js")?.toString()).toBe('console.log("second");');
      expect(contents.archiveWarnings?.some((w) => w.id === "ARCHIVE_DUPLICATE_PATH")).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("extracts ZIP with publisher.name-version prefix pattern", async () => {
    const manifest = JSON.stringify({
      name: "theme-allhallowseve-remake",
      publisher: "priskinski",
      version: "1.0.0",
    });

    const zipBuffer = createTestZip(
      [
        {
          name: "priskinski.theme-allhallowseve-remake-1.0.0/package.json",
          content: manifest,
        },
        {
          name: "priskinski.theme-allhallowseve-remake-1.0.0/node_modules/evil/index.js",
          content: 'require("child_process").exec("malware");',
        },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-malformed-prefix-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.manifest.name).toBe("theme-allhallowseve-remake");
      expect(contents.manifest.publisher).toBe("priskinski");
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("node_modules/evil/index.js")).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });
});

describe("decompression bomb protection", () => {
  const manifest = JSON.stringify({
    name: "bomb-test",
    publisher: "test",
    version: "1.0.0",
  });

  it("skips entry exceeding MAX_ENTRY_SIZE", async () => {
    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/bomb.bin",
        content: "small payload",
        spoofedUncompressedSize: MAX_ENTRY_SIZE + 1,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-bomb-entry-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("bomb.bin")).toBe(false);
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.warnings).toBeDefined();
      expect(contents.warnings?.length).toBe(1);
      expect(contents.warnings?.[0]).toContain("bomb.bin");
      expect(contents.warnings?.[0]).toContain("declared size");
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("skips entry with excessive compression ratio", async () => {
    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/suspicious.bin",
        content: "small payload",
        spoofedUncompressedSize: 10100,
        spoofedCompressedSize: 100,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-bomb-ratio-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("suspicious.bin")).toBe(false);
      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.warnings).toBeDefined();
      expect(contents.warnings?.[0]).toContain("compression ratio");
      expect(contents.warnings?.[0]).toContain(`${MAX_COMPRESSION_RATIO}:1`);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("skips entry when total extracted size would exceed limit", async () => {
    // Each entry is under MAX_ENTRY_SIZE but three together exceed MAX_TOTAL_SIZE.
    // Set spoofedCompressedSize to keep ratio under MAX_COMPRESSION_RATIO.
    const perEntry = MAX_ENTRY_SIZE - 1;
    const minCompressed = Math.ceil(perEntry / MAX_COMPRESSION_RATIO);

    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/big1.bin",
        content: "payload",
        spoofedUncompressedSize: perEntry,
        spoofedCompressedSize: minCompressed,
      },
      {
        name: "extension/big2.bin",
        content: "payload",
        spoofedUncompressedSize: perEntry,
        spoofedCompressedSize: minCompressed,
      },
      {
        name: "extension/big3.bin",
        content: "payload",
        spoofedUncompressedSize: perEntry,
        spoofedCompressedSize: minCompressed,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-bomb-total-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.warnings).toBeDefined();
      expect(contents.warnings?.length).toBeGreaterThanOrEqual(1);

      const totalWarning = contents.warnings?.find((w) => w.includes("total extracted size"));
      expect(totalWarning).toBeDefined();
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("allows entry at exact compression ratio boundary", async () => {
    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/border.bin",
        content: "some data here",
        spoofedUncompressedSize: 10000,
        spoofedCompressedSize: 100,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-bomb-boundary-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("border.bin")).toBe(true);
      expect(contents.warnings).toBeUndefined();
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("does not set warnings when no bombs detected", async () => {
    const zipBuffer = createTestZip(
      [
        { name: "extension/package.json", content: manifest },
        { name: "extension/normal.js", content: 'console.log("safe");' },
      ],
      { useDataDescriptor: false },
    );

    const vsixPath = join(tmpdir(), `test-no-bomb-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("normal.js")).toBe(true);
      expect(contents.warnings).toBeUndefined();
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("collects multiple warnings for different bomb types", async () => {
    const zipBuffer = createSpoofedZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/oversized.bin",
        content: "data",
        spoofedUncompressedSize: MAX_ENTRY_SIZE + 1,
      },
      {
        name: "extension/high-ratio.bin",
        content: "data",
        spoofedUncompressedSize: 20200,
        spoofedCompressedSize: 200,
      },
    ]);

    const vsixPath = join(tmpdir(), `test-bomb-multi-${Date.now()}.vsix`);
    await writeFile(vsixPath, zipBuffer);

    try {
      const contents = await extractVsix(vsixPath);

      expect(contents.files.has("package.json")).toBe(true);
      expect(contents.files.has("oversized.bin")).toBe(false);
      expect(contents.files.has("high-ratio.bin")).toBe(false);
      expect(contents.warnings).toBeDefined();
      expect(contents.warnings?.length).toBe(2);

      expect(contents.warnings?.some((w) => w.includes("declared size"))).toBe(true);
      expect(contents.warnings?.some((w) => w.includes("compression ratio"))).toBe(true);
    } finally {
      await rm(vsixPath, { force: true });
    }
  });
});
