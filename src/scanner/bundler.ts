/** Recognize generated content for entropy analysis without trusting its filename. */
export function isBundledCode(content: string): boolean {
  const markers = [
    /__webpack_require__|__webpack_modules__|webpackChunk/,
    /__esm\s*=|__export\s*=|var __defProp\s*=/,
    /parcelRequire|__vite_ssr_import__|__vite_ssr_dynamic_import__/,
    /\bimport\.meta\.hot\b|\/\/# sourceMappingURL=/,
  ];
  if (markers.some((marker) => marker.test(content))) return true;
  if (/\(function \(exports/.test(content) && /Object\.defineProperty\(exports,/.test(content))
    return true;
  const lines = content.split("\n");
  return content.length / lines.length > 200 && lines.some((line) => line.length > 1000);
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
