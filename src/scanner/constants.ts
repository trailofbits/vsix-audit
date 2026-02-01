/**
 * File extensions that can be scanned for code patterns.
 * Used by pattern, IOC, and unicode checks.
 */

/** Code files - JavaScript, TypeScript, and script files */
export const CODE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".mjs",
  ".cjs",
  ".jsx",
  ".tsx",
  ".ps1",
  ".sh",
  ".bat",
  ".cmd",
  ".py",
]);

/** Data files that may contain IOCs */
export const DATA_EXTENSIONS = new Set([".json"]);

/** Text files for unicode analysis */
export const TEXT_EXTENSIONS = new Set([".md", ".txt"]);

/** All scannable extensions for IOC checks (code + data) */
export const SCANNABLE_EXTENSIONS_IOC = new Set([...CODE_EXTENSIONS, ...DATA_EXTENSIONS]);

/** Scannable extensions for pattern checks (code only) */
export const SCANNABLE_EXTENSIONS_PATTERN = CODE_EXTENSIONS;

/** Scannable extensions for unicode checks (code + data + text) */
export const SCANNABLE_EXTENSIONS_UNICODE = new Set([
  ...CODE_EXTENSIONS,
  ...DATA_EXTENSIONS,
  ...TEXT_EXTENSIONS,
]);

export function isScannable(filename: string, extensions: Set<string>): boolean {
  const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  return extensions.has(ext);
}
