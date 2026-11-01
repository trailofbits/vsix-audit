import { describe, expect, it } from "vitest";
import { nativeCoverageWarnings } from "#internal/scanner/native.js";
import type { VsixContents } from "#internal/scanner/types.js";

function contents(file: string, buffer: Buffer): VsixContents {
  return {
    manifest: { name: "fixture", version: "1.0.0" },
    basePath: "/fixture",
    files: new Map([[file, buffer]]),
  };
}

describe("compiled content coverage", () => {
  it.each([".node", ".EXE", ".dll", ".dylib", ".so", ".wasm", ".class", ".jar", ".pyc"])(
    "reports executable extensions: %s",
    (extension) => {
      const warnings = nativeCoverageWarnings(contents(`binding${extension}`, Buffer.from("data")));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain(`binding${extension}`);
      expect(warnings[0]).toContain("native or compiled code");
      expect(warnings[0]).toContain("Inspect this file");
    },
  );

  it.each([
    "7f454c46",
    "0061736d",
    "feedface",
    "cefaedfe",
    "feedfacf",
    "cffaedfe",
    "cafebabe",
    "bebafeca",
    "cafebabf",
    "bfbafeca",
  ])("detects executable magic %s even with a script filename", (header) => {
    expect(nativeCoverageWarnings(contents("renamed.js", Buffer.from(header, "hex")))).toHaveLength(
      1,
    );
  });

  it("detects a renamed PE executable", () => {
    const buffer = Buffer.alloc(128);
    buffer.write("MZ");
    buffer.writeUInt32LE(80, 0x3c);
    buffer.write("PE\0\0", 80);
    expect(nativeCoverageWarnings(contents("renamed", buffer))).toHaveLength(1);
  });

  it.each([Buffer.alloc(0), Buffer.from("MZ"), Buffer.from("MZ".repeat(64)), Buffer.alloc(128)])(
    "does not classify arbitrary data as a PE executable",
    (buffer) => {
      expect(nativeCoverageWarnings(contents("data.txt", buffer))).toEqual([]);
    },
  );

  it("does not trust an in-bounds DOS header with an invalid PE signature", () => {
    const buffer = Buffer.alloc(128);
    buffer.write("MZ");
    buffer.writeUInt32LE(80, 0x3c);
    buffer.write("text", 80);
    expect(nativeCoverageWarnings(contents("data.txt", buffer))).toEqual([]);
  });
});
