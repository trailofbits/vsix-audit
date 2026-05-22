import { rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { scanExtension } from "./index.js";
import type { ScanOptions } from "./types.js";
import { MAX_ENTRY_SIZE } from "./vsix.js";

const SYNTHETIC_CORPUS_ROOT = join(import.meta.dirname, "..", "..", "test-corpus", "synthetic");

interface ZipFileSpec {
  name: string;
  content: string;
  spoofedCompressedSize?: number;
  spoofedUncompressedSize?: number;
}

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

function createZip(files: ZipFileSpec[]): Buffer {
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
    chunks.push(localHeader, compressed);

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

describe("production hardening regressions", () => {
  it("rejects invalid severity before scanning", async () => {
    await expect(
      scanExtension("missing.vsix", {
        output: "json",
        severity: "typo",
        network: false,
        modules: ["package"],
      } as unknown as ScanOptions),
    ).rejects.toThrow("Invalid severity");
  });

  it("reports skipped manifest entry points as coverage-degrading findings", async () => {
    const manifest = JSON.stringify({
      name: "skipped-main",
      publisher: "test",
      version: "1.0.0",
      main: "./main.js",
    });
    const zip = createZip([
      { name: "extension/package.json", content: manifest },
      {
        name: "extension/main.js",
        content: "require('child_process').exec('payload')",
        spoofedUncompressedSize: MAX_ENTRY_SIZE + 1,
      },
    ]);
    const vsixPath = join(tmpdir(), `vsix-audit-skipped-main-${Date.now()}.vsix`);
    await writeFile(vsixPath, zip);

    try {
      const result = await scanExtension(vsixPath, {
        output: "json",
        severity: "low",
        network: false,
        modules: ["package"],
      });

      expect(result.metadata.coverage?.degraded).toBe(true);
      expect(result.findings.some((f) => f.id === "ARCHIVE_SKIPPED_ENTRY")).toBe(true);
      const referenced = result.findings.find((f) => f.id === "ARCHIVE_REFERENCED_FILE_SKIPPED");
      expect(referenced).toBeDefined();
      expect(referenced?.severity).toBe("critical");
    } finally {
      await rm(vsixPath, { force: true });
    }
  });

  it("keeps multiple same-line IOC findings with different evidence", async () => {
    const result = await scanExtension(join(SYNTHETIC_CORPUS_ROOT, "ioc-dedupe"), {
      output: "json",
      severity: "low",
      network: false,
      modules: ["ioc"],
    });
    const c2Findings = result.findings.filter((finding) => finding.id === "KNOWN_C2_DOMAIN");
    const domains = c2Findings.map((finding) => finding.metadata?.["domain"]);

    expect(domains).toContain("niggboo.com");
    expect(domains).toContain("angelic.su");
    expect(c2Findings).toHaveLength(2);
  });
});
