/**
 * Bundler/minifier detection utilities.
 *
 * Bundled code (webpack, rollup, esbuild) naturally exhibits patterns that
 * look suspicious to security scanners:
 * - High entropy (minification removes whitespace, shortens names)
 * - Large string arrays (webpack string tables)
 * - new Function() (webpack module system)
 * - Dynamic requires (webpack's __webpack_require__)
 * - Zero-width chars (from bundled i18n libraries)
 *
 * This module helps detect bundled code so checks can adjust thresholds.
 */

export interface BundlerInfo {
  isBundled: boolean;
  bundler: "webpack" | "rollup" | "esbuild" | "parcel" | "vite" | "unknown" | null;
  isMinified: boolean;
  confidence: "high" | "medium" | "low";
}

/**
 * Detect if a file is bundled/minified code.
 */
export function detectBundler(content: string, filename: string): BundlerInfo {
  const result: BundlerInfo = {
    isBundled: false,
    bundler: null,
    isMinified: false,
    confidence: "low",
  };

  // Check filename patterns first
  if (
    filename.endsWith(".bundle.js") ||
    filename.endsWith(".min.js") ||
    filename.endsWith(".chunk.js") ||
    /vendors[-~]/.test(filename) ||
    /\d+\..*\.js$/.test(filename) // numeric chunk IDs like 540.extension.js
  ) {
    result.isBundled = true;
    result.confidence = "medium";
  }

  // Webpack signatures
  if (
    /__webpack_require__/.test(content) ||
    /__webpack_modules__/.test(content) ||
    /webpackChunk/.test(content) ||
    /\/\*\*\*\/ "\d+":/.test(content) // webpack module IDs
  ) {
    result.isBundled = true;
    result.bundler = "webpack";
    result.confidence = "high";
  }

  // Rollup signatures
  if (/\(function \(exports/.test(content) && /Object\.defineProperty\(exports,/.test(content)) {
    result.isBundled = true;
    result.bundler = "rollup";
    result.confidence = "high";
  }

  // Esbuild signatures
  if (
    /__esm\s*=/.test(content) ||
    /__export\s*=/.test(content) ||
    /var __defProp\s*=/.test(content)
  ) {
    result.isBundled = true;
    result.bundler = "esbuild";
    result.confidence = "high";
  }

  // Parcel signatures
  if (/parcelRequire/.test(content)) {
    result.isBundled = true;
    result.bundler = "parcel";
    result.confidence = "high";
  }

  // Check for minification indicators
  const lines = content.split("\n");
  if (lines.length > 0) {
    // Very long lines indicate minification
    const avgLineLength = content.length / Math.max(lines.length, 1);
    const hasVeryLongLines = lines.some((line) => line.length > 1000);

    if (hasVeryLongLines && avgLineLength > 200) {
      result.isMinified = true;
      if (!result.isBundled) {
        result.isBundled = true;
        result.bundler = "unknown";
        result.confidence = "medium";
      }
    }
  }

  // Source map reference is a strong signal of bundled code
  if (/\/\/# sourceMappingURL=/.test(content)) {
    if (!result.isBundled) {
      result.isBundled = true;
      result.bundler = "unknown";
      result.confidence = "medium";
    }
  }

  return result;
}

/**
 * Check if content has genuine obfuscation (not just bundling).
 *
 * Bundled code naturally has some "obfuscation-like" patterns:
 * - Short variable names (minification)
 * - High entropy (compressed)
 * - Large string arrays (webpack)
 *
 * This distinguishes intentional obfuscation from normal bundling.
 */
export function hasGenuineObfuscation(content: string): boolean {
  // Hex variable names like _0x4a3b are a signature of javascript-obfuscator
  // Bundlers use short names like a, b, c, not hex patterns
  const hexVarMatches = content.match(/_0x[a-f0-9]{4,}/gi);
  if (hexVarMatches && hexVarMatches.length > 5) {
    return true;
  }

  // eval(atob(...)) or eval(Buffer.from(...)) are obfuscation, not bundling
  if (/eval\s*\(\s*(?:atob|Buffer\.from)/.test(content)) {
    return true;
  }

  // String.fromCharCode with many args is obfuscation
  if (/String\.fromCharCode\s*\([0-9,\s]{30,}\)/.test(content)) {
    return true;
  }

  // Array-based obfuscation with rotation
  if (/\]\s*\[\s*['"]shift['"]\s*\]\s*\(\s*\)/.test(content)) {
    return true;
  }

  return false;
}
