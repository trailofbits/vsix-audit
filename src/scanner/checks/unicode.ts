import type { Finding, Severity, VsixContents } from "../types.js";

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

const SCANNABLE_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".mjs",
  ".cjs",
  ".jsx",
  ".tsx",
  ".json",
  ".md",
  ".txt",
]);

function isScannable(filename: string): boolean {
  const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  return SCANNABLE_EXTENSIONS.has(ext);
}

function findLineAndColumn(
  content: string,
  index: number,
): { line: number; column: number } {
  const beforeMatch = content.slice(0, index);
  const lines = beforeMatch.split("\n");
  const line = lines.length;
  const column = (lines.at(-1)?.length ?? 0) + 1;
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
// This is obfuscation - using unicode escapes for normal characters
const UNICODE_ASCII_ESCAPE_REGEX = /\\u00[2-7][0-9a-fA-F]/g;

// Cyrillic homoglyphs that look like Latin letters
// а(U+0430)/a, с(U+0441)/c, е(U+0435)/e, о(U+043E)/o, р(U+0440)/p, х(U+0445)/x, у(U+0443)/y
// Also uppercase: А(U+0410)/A, В(U+0412)/B, С(U+0421)/C, Е(U+0415)/E, Н(U+041D)/H, etc.
const CYRILLIC_LOOKALIKE_REGEX = /[\u0430\u0441\u0435\u043E\u0440\u0445\u0443\u0410\u0412\u0421\u0415\u041D\u041A\u041C\u041E\u0420\u0422\u0425]/g;

// Additional invisible/confusable characters
// U+00AD Soft hyphen, U+034F Combining grapheme joiner, U+115F-1160 Hangul fillers
// U+17B4-17B5 Khmer vowels, U+180E Mongolian vowel separator
const OTHER_INVISIBLE_REGEX = /[\u00AD\u034F\u115F\u1160\u17B4\u17B5\u180E\u2060-\u2064\u206A-\u206F]/g;

function detectPattern(
  content: string,
  regex: RegExp,
  minMatches = 1,
): UnicodeMatch[] {
  const matches: UnicodeMatch[] = [];
  const r = new RegExp(regex.source, regex.flags);
  let match: RegExpExecArray | null;

  while ((match = r.exec(content)) !== null) {
    const { line, column } = findLineAndColumn(content, match.index);
    matches.push({
      line,
      column,
      matched: match[0],
      context: getContext(content, match.index, match[0].length),
    });
  }

  return matches.length >= minMatches ? matches : [];
}

function hasExecutionContext(content: string): boolean {
  // Check if invisible chars appear near code execution patterns
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
  ];
  return execPatterns.some((p) => p.test(content));
}

const UNICODE_RULES: UnicodeRule[] = [
  {
    id: "ZERO_WIDTH_CHARS",
    title: "Zero-width characters detected",
    description:
      "File contains zero-width Unicode characters (U+200B-200D, U+FEFF). These invisible characters can hide malicious code or be used for steganography.",
    severity: "high",
    detect: (content) => detectPattern(content, ZERO_WIDTH_REGEX, 3),
  },
  {
    id: "VARIATION_SELECTOR",
    title: "Unicode variation selectors detected (GlassWorm technique)",
    description:
      "File contains Unicode variation selectors (U+FE00-FE0F). This is the technique used by GlassWorm malware to hide executable code in plain sight.",
    severity: "critical",
    detect: (content) => detectPattern(content, VARIATION_SELECTOR_REGEX, 1),
  },
  {
    id: "BIDI_OVERRIDE",
    title: "Bidirectional text override detected (Trojan Source)",
    description:
      "File contains Unicode bidirectional override characters (U+202A-202E). This is the Trojan Source attack technique that can make malicious code appear benign by reordering how text is displayed.",
    severity: "critical",
    detect: (content) => detectPattern(content, BIDI_OVERRIDE_REGEX, 1),
  },
  {
    id: "UNICODE_ASCII_ESCAPE",
    title: "Unicode escape sequences for ASCII characters",
    description:
      "File uses Unicode escape sequences (\\u00XX) for normal ASCII characters. This is a common obfuscation technique to hide string contents from static analysis.",
    severity: "medium",
    detect: (content) => detectPattern(content, UNICODE_ASCII_ESCAPE_REGEX, 5),
  },
  {
    id: "CYRILLIC_HOMOGLYPH",
    title: "Cyrillic homoglyph characters detected",
    description:
      "File contains Cyrillic characters that visually resemble Latin letters (e.g., Cyrillic 'а' vs Latin 'a'). This can be used for homoglyph attacks to disguise malicious identifiers.",
    severity: "high",
    detect: (content, filename) => {
      // Only flag in code files, not documentation
      if (filename.endsWith(".md") || filename.endsWith(".txt")) {
        return [];
      }
      return detectPattern(content, CYRILLIC_LOOKALIKE_REGEX, 1);
    },
  },
  {
    id: "OTHER_INVISIBLE_CHARS",
    title: "Other invisible Unicode characters detected",
    description:
      "File contains invisible Unicode characters (soft hyphens, combining marks, format controls). These can be used to hide malicious content.",
    severity: "medium",
    detect: (content) => detectPattern(content, OTHER_INVISIBLE_REGEX, 3),
  },
  {
    id: "INVISIBLE_CODE_EXECUTION",
    title: "Invisible characters near code execution",
    description:
      "File contains invisible Unicode characters in proximity to code execution functions (eval, Function, exec). This is a strong indicator of hidden malicious code.",
    severity: "critical",
    detect: (content) => {
      if (!hasExecutionContext(content)) {
        return [];
      }
      // Check for any invisible chars when execution context exists
      const allInvisible = new RegExp(
        `${ZERO_WIDTH_REGEX.source}|${VARIATION_SELECTOR_REGEX.source}|${BIDI_OVERRIDE_REGEX.source}`,
        "g",
      );
      return detectPattern(content, allInvisible, 1);
    },
  },
];

export function checkUnicode(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename)) continue;

    const content = buffer.toString("utf8");

    for (const rule of UNICODE_RULES) {
      const matches = rule.detect(content, filename);

      if (matches.length === 0) continue;

      // Create one finding per rule per file, with all matches in metadata
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
        category: "unicode",
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
              [...m.matched].map((c) => `U+${c.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`).join(", "),
            ),
        },
      });
    }
  }

  return findings;
}
