import type { BundlerInfo } from "../bundler.js";
import { detectBundler } from "../bundler.js";
import {
  isScannable,
  SCANNABLE_EXTENSIONS_PATTERN,
  SCANNABLE_EXTENSIONS_UNICODE,
} from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import {
  computeLineStarts,
  findLineNumberByIndex,
  getStringContent,
  offsetToColumn,
  offsetToLine,
} from "../utils.js";

/**
 * Obfuscation detection module.
 *
 * This module handles detection that requires TypeScript precision:
 * - Shannon entropy calculation (YARA can't compute entropy)
 * - Unicode codepoint detection (precise ranges, i18n awareness)
 *
 * Pattern-based obfuscation (hex vars, fromCharCode, etc.) is handled by YARA rules
 * in zoo/signatures/yara/obfuscation_patterns.yar
 */

// --- Type Definitions ---

interface EntropyMatch {
  index: number;
  matched: string;
  score: number;
}

interface UnicodeRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  detect: (content: string, filename: string) => UnicodeMatch[];
}

interface UnicodeMatch {
  line: number;
  column: number;
  matched: string;
  context: string;
}

// ============================================================================
// SHARED UTILITIES
// ============================================================================

/**
 * Check if file is in node_modules (third-party dependencies).
 * These are not extension code and generate many false positives.
 */
function isNodeModules(filename: string): boolean {
  return filename.includes("node_modules/") || filename.includes("node_modules\\");
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy indicates more randomness, often a sign of obfuscation.
 * Normal code: ~4.5 bits/char, obfuscated: >5.5
 */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] ?? 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Find high-entropy regions in code (potential obfuscation).
 * Uses a sliding window approach.
 */
function findHighEntropyRegions(
  content: string,
  windowSize = 200,
  threshold = 5.5,
): { start: number; end: number; entropy: number }[] {
  const regions: { start: number; end: number; entropy: number }[] = [];
  const step = 50;

  for (let i = 0; i < content.length - windowSize; i += step) {
    const window = content.slice(i, i + windowSize);

    // Skip whitespace-heavy regions
    const nonWhitespace = window.replace(/\s/g, "");
    if (nonWhitespace.length < windowSize * 0.3) continue;

    const entropy = shannonEntropy(nonWhitespace);
    if (entropy > threshold) {
      // Merge with previous region if overlapping
      const last = regions.at(-1);
      if (last && i < last.end + step) {
        last.end = i + windowSize;
        last.entropy = Math.max(last.entropy, entropy);
      } else {
        regions.push({ start: i, end: i + windowSize, entropy });
      }
    }
  }

  return regions;
}

function checkEntropy(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;
    // Skip node_modules - third-party deps generate many false positives
    if (isNodeModules(filename)) continue;

    const content = getStringContent(contents, filename, buffer);

    // Skip bundled code - minification naturally increases entropy
    const bundlerInfo = detectBundler(
      content,
      filename,
      contents.cache as Map<string, BundlerInfo> | undefined,
    );
    if (bundlerInfo.isBundled) continue;

    const regions = findHighEntropyRegions(content);
    if (regions.length === 0) continue;

    const key = `OBFUSCATION_HIGH_ENTROPY:${filename}`;
    if (seenFindings.has(key)) continue;
    seenFindings.add(key);

    const firstRegion = regions[0];
    if (!firstRegion) continue;

    const matches: EntropyMatch[] = regions.map((region) => ({
      index: region.start,
      matched: `Entropy: ${region.entropy.toFixed(2)} bits/char`,
      score: Math.min(90, Math.floor(region.entropy * 15)),
    }));

    findings.push({
      id: "OBFUSCATION_HIGH_ENTROPY",
      title: "High entropy code region",
      description:
        "Code region has unusually high Shannon entropy (randomness). This often indicates obfuscated or encoded content.",
      severity: "medium",
      category: "obfuscation",
      location: {
        file: filename,
        line: findLineNumberByIndex(content, firstRegion.start),
      },
      metadata: {
        matchCount: matches.length,
        matched: matches[0]?.matched,
        obfuscationScore: Math.max(...matches.map((m) => m.score)),
        legitimateUses: ["Compressed data", "Base64 content", "Hash strings"],
        redFlags: ["Near eval/Function", "Large continuous regions"],
      },
    });
  }

  return findings;
}

// ============================================================================
// UNICODE HIDING DETECTION
// ============================================================================

function findLineAndColumn(index: number, lineStarts: number[]): { line: number; column: number } {
  const line = offsetToLine(index, lineStarts);
  const column = offsetToColumn(index, lineStarts) + 1;
  return { line, column };
}

function getContext(content: string, index: number, length: number): string {
  const start = Math.max(0, index - 20);
  const end = Math.min(content.length, index + length + 20);
  let ctx = content.slice(start, end);
  if (start > 0) ctx = "..." + ctx;
  if (end < content.length) ctx = ctx + "...";
  return ctx.replace(/[\n\r]/g, "\\n").slice(0, 80);
}

// Zero-width characters: U+200B-200D, U+FEFF
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF]/g;

// Variation selectors: U+FE00-FE0F (GlassWorm technique)
const VARIATION_SELECTOR_REGEX = /[\uFE00-\uFE0F]/g;

// Bidirectional overrides: U+202A-202E (Trojan Source attack)
const BIDI_OVERRIDE_REGEX = /[\u202A-\u202E]/g;

// Unicode escapes for ASCII: \u00XX where XX is 20-7E (printable ASCII)
const UNICODE_ASCII_ESCAPE_REGEX = /\\u00[2-7][0-9a-fA-F]/g;

// Cyrillic homoglyphs paired with the Latin letter they impersonate.
// Used by the mixed-script detector to identify the homoglyph half of a
// mixed token. Each entry is independently auditable.
const CYRILLIC_TO_LATIN_HOMOGLYPHS: ReadonlyArray<readonly [string, string]> = [
  // Lowercase
  ["\u0430", "a"], // U+0430 CYRILLIC SMALL LETTER A
  ["\u0441", "c"], // U+0441 CYRILLIC SMALL LETTER ES
  ["\u0435", "e"], // U+0435 CYRILLIC SMALL LETTER IE
  ["\u043E", "o"], // U+043E CYRILLIC SMALL LETTER O
  ["\u0440", "p"], // U+0440 CYRILLIC SMALL LETTER ER
  ["\u0445", "x"], // U+0445 CYRILLIC SMALL LETTER HA
  ["\u0443", "y"], // U+0443 CYRILLIC SMALL LETTER U
  // Uppercase
  ["\u0410", "A"], // U+0410 CYRILLIC CAPITAL LETTER A
  ["\u0412", "B"], // U+0412 CYRILLIC CAPITAL LETTER VE
  ["\u0421", "C"], // U+0421 CYRILLIC CAPITAL LETTER ES
  ["\u0415", "E"], // U+0415 CYRILLIC CAPITAL LETTER IE
  ["\u041D", "H"], // U+041D CYRILLIC CAPITAL LETTER EN
  ["\u041A", "K"], // U+041A CYRILLIC CAPITAL LETTER KA
  ["\u041C", "M"], // U+041C CYRILLIC CAPITAL LETTER EM
  ["\u041E", "O"], // U+041E CYRILLIC CAPITAL LETTER O
  ["\u0420", "P"], // U+0420 CYRILLIC CAPITAL LETTER ER
  ["\u0422", "T"], // U+0422 CYRILLIC CAPITAL LETTER TE
  ["\u0425", "X"], // U+0425 CYRILLIC CAPITAL LETTER HA
];
const CYRILLIC_LOOKALIKE_SET = new Set(CYRILLIC_TO_LATIN_HOMOGLYPHS.map(([cyr]) => cyr));

// Additional invisible/confusable characters
const OTHER_INVISIBLE_REGEX =
  /(?:\u00AD|\u034F|\u115F|\u1160|\u17B4|\u17B5|\u180E|[\u2060-\u2064]|[\u206A-\u206F])/g;

function detectUnicodePattern(
  content: string,
  regex: RegExp,
  minMatches = 1,
  lineStarts?: number[],
): UnicodeMatch[] {
  const matches: UnicodeMatch[] = [];
  const r = new RegExp(regex.source, regex.flags);
  const starts = lineStarts ?? computeLineStarts(content);
  let match: RegExpExecArray | null;

  while ((match = r.exec(content)) !== null) {
    const { line, column } = findLineAndColumn(match.index, starts);
    matches.push({
      line,
      column,
      matched: match[0],
      context: getContext(content, match.index, match[0].length),
    });
  }

  return matches.length >= minMatches ? matches : [];
}

/**
 * Flags Cyrillic homoglyph attacks: a single contiguous run of letters that
 * mixes ASCII Latin (A–Z, a–z) with Cyrillic look-alike chars (а, о, е …).
 *
 * The run-tokenizer also consumes `\uXXXX` source escapes as a single
 * "letter" so attacks that hide the homoglyph behind an escape sequence
 * (e.g., `gоogle` in JS/JSON source) are flagged the same way as the
 * literal-character form.
 *
 * Pure-Cyrillic words (e.g., "русский" in a localization array) are not
 * flagged — homoglyph attacks require interleaving Cyrillic into Latin.
 */
function detectMixedScriptCyrillicHomoglyphs(content: string): UnicodeMatch[] {
  const matches: UnicodeMatch[] = [];
  // A "letter" is either a literal Latin/Cyrillic char or a `\uXXXX`
  // source escape. Word breaks (whitespace, punctuation, digits) split
  // tokens, so "русский" and "google" never merge into one run.
  const wordPattern = /(?:[A-Za-zЀ-ӿ]|\\u[0-9A-Fa-f]{4})+/g;
  const starts = computeLineStarts(content);
  let match: RegExpExecArray | null;

  while ((match = wordPattern.exec(content)) !== null) {
    const run = match[0];
    let hasLatin = false;
    let firstHomoglyphIdx = -1;

    let i = 0;
    while (i < run.length) {
      let ch: string;
      let advance: number;
      if (run[i] === "\\" && run[i + 1] === "u" && /[0-9A-Fa-f]{4}/.test(run.slice(i + 2, i + 6))) {
        ch = String.fromCodePoint(parseInt(run.slice(i + 2, i + 6), 16));
        advance = 6;
      } else {
        ch = run[i]!;
        advance = 1;
      }

      const code = ch.charCodeAt(0);
      if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
        hasLatin = true;
      } else if (firstHomoglyphIdx === -1 && CYRILLIC_LOOKALIKE_SET.has(ch)) {
        firstHomoglyphIdx = i;
      }

      i += advance;
    }

    if (hasLatin && firstHomoglyphIdx !== -1) {
      const absIdx = match.index + firstHomoglyphIdx;
      const { line, column } = findLineAndColumn(absIdx, starts);
      matches.push({
        line,
        column,
        matched: run.slice(firstHomoglyphIdx, firstHomoglyphIdx + (run[firstHomoglyphIdx] === "\\" ? 6 : 1)),
        context: getContext(content, absIdx, 1),
      });
    }
  }

  return matches;
}

/**
 * Check if the file appears to be primarily i18n/localization content.
 */
function isI18nFile(filename: string, content: string): boolean {
  const i18nPatterns = [
    /locales?\//i,
    /i18n\//i,
    /translations?\//i,
    /lang\//i,
    /messages/i,
    /\.l10n\./i,
    /nls\./i,
    // moment locale files (e.g., moment/locale/ku.js)
    /moment\/.*locale/i,
    // Encoding tables (iconv-lite encodings/tables/*.js)
    /encodings?\/(tables|sbcs)/i,
    // HTML entities data
    /entities\.json$/i,
    // Emoji data files
    /emoji\.json$/i,
    // CLI spinners data
    /spinners\.json$/i,
    // Public Suffix List
    /psl\//i,
    // VS Code NLS localization files (package.nls.*.json)
    /package\.nls\.[a-z]{2}(-[a-z]{2})?\.json$/i,
  ];
  if (i18nPatterns.some((p) => p.test(filename))) {
    return true;
  }

  if (filename.endsWith(".json")) {
    const keyValuePairs = (content.match(/"[^"]+"\s*:\s*"[^"]+"/g) ?? []).length;
    const lines = content.split("\n").length;
    if (keyValuePairs / lines > 0.5 && keyValuePairs > 10) {
      return true;
    }
  }

  // Persian (Farsi) and Arabic scripts use zero-width non-joiner (U+200C) legitimately
  // for proper text rendering. Detect these scripts by their Unicode ranges.
  const hasPersianArabicScript = /[\u0600-\u06FF\u0750-\u077F]/.test(content);
  if (hasPersianArabicScript && filename.endsWith(".json")) {
    return true;
  }

  return false;
}

/**
 * Check if file has legitimate RTL text support (math, diagrams, language files).
 */
function isRtlFile(filename: string): boolean {
  const rtlPatterns = [
    /katex/i, // KaTeX math rendering
    /mermaid/i, // Mermaid diagram library
    /mathjax/i, // MathJax math rendering
    /drawio.*\/(dia_he|dia_fa|dia_ar)/i, // DrawIO Hebrew/Farsi/Arabic language files
    /_he\.txt$/i, // Hebrew language files
    /_fa\.txt$/i, // Farsi language files
    /_ar\.txt$/i, // Arabic language files
  ];
  return rtlPatterns.some((p) => p.test(filename));
}

/**
 * Check if invisible characters are in proximity to execution patterns.
 */
function hasExecutionInProximity(
  content: string,
  invisibleIndex: number,
  proximityChars = 200,
): boolean {
  const start = Math.max(0, invisibleIndex - proximityChars);
  const end = Math.min(content.length, invisibleIndex + proximityChars);
  const region = content.slice(start, end);

  const execPatterns = [
    /eval\s*\(/i,
    /Function\s*\(/i,
    /exec\s*\(/i,
    /spawn\s*\(/i,
    /execSync\s*\(/i,
    /child_process/i,
    /\.\s*call\s*\(/,
    /\.\s*apply\s*\(/,
    /new\s+Function/i,
    /atob\s*\(/i,
    /Buffer\.from/i,
  ];
  return execPatterns.some((p) => p.test(region));
}

// Rules that should be skipped for bundled code and node_modules
const SKIP_UNICODE_FOR_BUNDLED = new Set([
  "ZERO_WIDTH_CHARS",
  "CYRILLIC_HOMOGLYPH",
  "OTHER_INVISIBLE_CHARS",
  "UNICODE_ASCII_ESCAPE",
]);

// Rules that should be skipped for node_modules (third-party deps)
// Critical rules (VARIATION_SELECTOR, BIDI_OVERRIDE, INVISIBLE_CODE_EXECUTION) still run
const SKIP_UNICODE_FOR_NODE_MODULES = new Set([
  "ZERO_WIDTH_CHARS",
  "CYRILLIC_HOMOGLYPH",
  "OTHER_INVISIBLE_CHARS",
  "UNICODE_ASCII_ESCAPE",
  "OBFUSCATION_HIGH_ENTROPY",
]);

const UNICODE_RULES: UnicodeRule[] = [
  {
    id: "ZERO_WIDTH_CHARS",
    title: "Zero-width characters detected",
    description:
      "File contains zero-width Unicode characters (U+200B-200D, U+FEFF). These invisible characters can hide malicious code or be used for steganography.",
    severity: "high",
    detect: (content, filename) => {
      // Skip i18n files - Persian, Arabic, Kurdish etc. use U+200C (ZWNJ) legitimately
      if (isI18nFile(filename, content)) return [];
      return detectUnicodePattern(content, ZERO_WIDTH_REGEX, 3);
    },
  },
  {
    id: "VARIATION_SELECTOR",
    title: "Unicode variation selectors detected (GlassWorm technique)",
    description:
      "File contains many Unicode variation selectors (U+FE00-FE0F). GlassWorm malware uses these to hide executable code.",
    severity: "critical",
    detect: (content, filename) => {
      // Skip emoji/entity data files that legitimately use variation selectors
      const emojiDataPatterns = [
        /emoji/i,
        /entities/i,
        /spinners/i,
        /\.md$/i, // README files often have emoji
        /gemoji/i, // GitHub emoji library
        /twemoji/i, // Twitter emoji
        /node-emoji/i, // node-emoji package
        /unicode.*data/i, // Unicode data files
        /emojis?\.(json|js|ts)$/i, // emoji data files
      ];
      if (emojiDataPatterns.some((p) => p.test(filename))) return [];

      // If file contains many actual emoji characters, it's likely legitimate emoji data
      // Emoji ranges: Emoticons, Dingbats, Symbols, Flags, etc.
      // eslint-disable-next-line no-misleading-character-class
      const emojiPattern = /[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu;
      const emojiMatches = content.match(emojiPattern);
      if (emojiMatches && emojiMatches.length > 100) return [];

      // GlassWorm uses hundreds of variation selectors; 50 is well above normal emoji use
      return detectUnicodePattern(content, VARIATION_SELECTOR_REGEX, 50);
    },
  },
  {
    id: "BIDI_OVERRIDE",
    title: "Bidirectional text override detected (Trojan Source)",
    description:
      "File contains Unicode bidirectional override characters (U+202A-202E). This is the Trojan Source attack technique.",
    severity: "critical",
    detect: (content, filename) => {
      // Skip files with legitimate RTL text support (math, diagrams, language files)
      if (isRtlFile(filename)) return [];
      return detectUnicodePattern(content, BIDI_OVERRIDE_REGEX, 1);
    },
  },
  {
    id: "UNICODE_ASCII_ESCAPE",
    title: "Unicode escape sequences for ASCII characters",
    description:
      "File uses Unicode escape sequences (\\u00XX) for normal ASCII characters. This is a common obfuscation technique.",
    severity: "medium",
    detect: (content) => detectUnicodePattern(content, UNICODE_ASCII_ESCAPE_REGEX, 5),
  },
  {
    id: "CYRILLIC_HOMOGLYPH",
    title: "Cyrillic homoglyph characters detected",
    description:
      "File contains a Latin token with Cyrillic look-alike characters mixed in (e.g., 'gооgle' with Cyrillic 'о'). Pure Cyrillic words are not flagged — only mixed-script tokens, which are the actual attack pattern.",
    severity: "high",
    detect: (content, filename) => {
      if (filename.endsWith(".md") || filename.endsWith(".txt")) {
        return [];
      }
      if (isI18nFile(filename, content)) {
        return [];
      }
      return detectMixedScriptCyrillicHomoglyphs(content);
    },
  },
  {
    id: "OTHER_INVISIBLE_CHARS",
    title: "Other invisible Unicode characters detected",
    description:
      "File contains invisible Unicode characters (soft hyphens, combining marks, format controls).",
    severity: "medium",
    detect: (content) => detectUnicodePattern(content, OTHER_INVISIBLE_REGEX, 3),
  },
  {
    id: "INVISIBLE_CODE_EXECUTION",
    title: "Invisible characters near code execution",
    description:
      "File contains many invisible Unicode characters in proximity to code execution functions. Strong indicator of hidden malicious code.",
    severity: "critical",
    detect: (content, filename) => {
      if (isI18nFile(filename, content)) {
        return [];
      }

      const suspiciousInvisible = new RegExp(
        `${VARIATION_SELECTOR_REGEX.source}|${BIDI_OVERRIDE_REGEX.source}`,
        "g",
      );
      const matches = detectUnicodePattern(content, suspiciousInvisible, 5);

      return matches.filter((m) => {
        const matchIndex =
          content.slice(0, m.line).split("\n").length > 1
            ? content
                .split("\n")
                .slice(0, m.line - 1)
                .join("\n").length + m.column
            : m.column;
        return hasExecutionInProximity(content, matchIndex);
      });
    },
  },
];

function checkUnicodeHiding(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_UNICODE)) continue;

    const content = getStringContent(contents, filename, buffer);
    const bundlerInfo = detectBundler(
      content,
      filename,
      contents.cache as Map<string, BundlerInfo> | undefined,
    );
    const inNodeModules = isNodeModules(filename);

    for (const rule of UNICODE_RULES) {
      // Skip non-critical rules for bundled code
      if (bundlerInfo.isBundled && SKIP_UNICODE_FOR_BUNDLED.has(rule.id)) {
        continue;
      }
      // Skip non-critical rules for node_modules (third-party deps)
      if (inNodeModules && SKIP_UNICODE_FOR_NODE_MODULES.has(rule.id)) {
        continue;
      }

      const matches = rule.detect(content, filename);
      if (matches.length === 0) continue;

      const key = `${rule.id}:${filename}`;
      if (seenFindings.has(key)) continue;
      seenFindings.add(key);

      const firstMatch = matches[0];
      if (!firstMatch) continue;

      findings.push({
        id: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        category: "obfuscation",
        location: {
          file: filename,
          line: firstMatch.line,
          column: firstMatch.column,
        },
        metadata: {
          matchCount: matches.length,
          firstMatch: firstMatch.context,
          codePoints: matches
            .slice(0, 5)
            .map((m) =>
              [...m.matched]
                .map((c) => `U+${c.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`)
                .join(", "),
            ),
        },
      });
    }
  }

  return findings;
}

// ============================================================================
// MAIN EXPORT
// ============================================================================

export function checkObfuscation(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];

  // Check entropy in code files (1 rule - YARA can't calculate entropy)
  findings.push(...checkEntropy(contents));

  // Check Unicode hiding in all text files (7 rules)
  findings.push(...checkUnicodeHiding(contents));

  return findings;
}
