import { isUtf8 } from "node:buffer";
import type { Finding, YaraStringMatch } from "#internal/scanner/types.js";

function validOffset(value: unknown, size: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= size;
}

function readStringMatch(entry: unknown, buffer: Buffer): YaraStringMatch {
  if (typeof entry !== "object" || entry === null) {
    throw new Error("YARA-X string evidence must be an object.");
  }
  const match = entry as Record<string, unknown>;
  if (typeof match["identifier"] !== "string" || typeof match["match"] !== "string") {
    throw new Error("YARA-X string evidence must have an identifier and excerpt.");
  }
  const offset = match["offset"];
  if (!validOffset(offset, buffer.length)) {
    throw new Error("YARA-X string offset is outside the scanned file.");
  }
  return { identifier: match["identifier"], offset, match: match["match"] };
}

/** Validate YARA-X string evidence against the file's byte boundaries. */
export function readStringMatches(value: unknown, buffer: Buffer): YaraStringMatch[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("YARA-X strings must be an array.");
  return (value as unknown[]).map((entry) => readStringMatch(entry, buffer));
}

/** Locate the first matching byte, with one-based text coordinates when UTF-8 is valid. */
export function evidenceLocation(
  file: string,
  matches: YaraStringMatch[],
  buffer: Buffer,
): NonNullable<Finding["location"]> {
  if (matches.length === 0) return { file };
  let byteOffset = buffer.length;
  for (const match of matches) byteOffset = Math.min(byteOffset, match.offset);
  if (buffer.includes(0) || !isUtf8(buffer)) return { file, byteOffset };
  const prefix = buffer.subarray(0, byteOffset);
  if (!isUtf8(prefix)) return { file, byteOffset };
  let line = 1;
  for (const byte of prefix) {
    if (byte === 0x0a) line++;
  }
  const column = prefix.subarray(prefix.lastIndexOf(0x0a) + 1).toString("utf8").length + 1;
  return { file, byteOffset, line, column };
}
