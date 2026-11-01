import { extname } from "node:path";
import type { VsixContents } from "#internal/scanner/types.js";

const EXECUTABLE_EXTENSIONS = new Set([
  ".node",
  ".exe",
  ".dll",
  ".dylib",
  ".so",
  ".wasm",
  ".class",
  ".jar",
  ".war",
  ".ear",
  ".pyc",
  ".pyo",
]);
const EXECUTABLE_HEADERS = new Set([
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
]);

function isPortableExecutable(buffer: Buffer): boolean {
  if (buffer.length < 64 || buffer.subarray(0, 2).toString("ascii") !== "MZ") return false;
  const offset = buffer.readUInt32LE(0x3c);
  return (
    offset <= buffer.length - 4 &&
    buffer.subarray(offset, offset + 4).equals(Buffer.from([0x50, 0x45, 0, 0]))
  );
}

/** Recognize compiled formats by extension or executable header, including renamed binaries. */
export function isCompiledFile(file: string, buffer: Buffer): boolean {
  return (
    EXECUTABLE_EXTENSIONS.has(extname(file).toLowerCase()) ||
    EXECUTABLE_HEADERS.has(buffer.subarray(0, 4).toString("hex")) ||
    isPortableExecutable(buffer)
  );
}

/** Report executable formats whose behavior the script analyzers cannot inspect. */
export function nativeCoverageWarnings(contents: VsixContents): string[] {
  const warnings: string[] = [];
  for (const [file, buffer] of contents.files) {
    if (!isCompiledFile(file, buffer)) continue;
    warnings.push(
      `Limited analysis of ${JSON.stringify(file)}: native or compiled code is outside ` +
        "the script analyzers. Hash and byte-pattern checks do not analyze its behavior. " +
        "Inspect this file with tools for its executable format.",
    );
  }
  return warnings;
}
