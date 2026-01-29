import { detectBundler, hasGenuineObfuscation } from "../bundler.js";
import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type { Finding, Severity, VsixContents } from "../types.js";
import { findLineNumberByIndex } from "../utils.js";

interface ObfuscationIndicator {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  detect: (content: string) => ObfuscationMatch[];
  legitimateUses?: string[];
  redFlags?: string[];
}

interface ObfuscationMatch {
  index: number;
  matched: string;
  score: number;
}

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

// Obfuscation patterns
const HEX_VARIABLE_REGEX = /_0x[a-f0-9]{4,}/gi;
const CHAR_CODE_ARRAY_REGEX = /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/g;
const EVAL_ATOB_CHAIN_REGEX = /eval\s*\(\s*(?:atob|Buffer\.from)\s*\(/gi;
const FUNCTION_CONSTRUCTOR_REGEX = /new\s+Function\s*\(\s*["'`]/g;
const ARRAY_ROTATION_REGEX = /\[\s*(['"][^'"]*['"](?:\s*,\s*['"][^'"]*['"]){10,})\s*\]/g;
const BRACKET_PROPERTY_CHAIN_REGEX =
  /\[\s*['"][a-zA-Z]+['"]\s*\](?:\s*\[\s*['"][a-zA-Z]+['"]\s*\]){3,}/g;
const ESCAPE_SEQUENCE_HEAVY_REGEX = /(?:\\x[a-f0-9]{2}){10,}/gi;
const DECIMAL_ARRAY_REGEX = /\[\s*(?:\d{2,3}\s*,\s*){20,}/g;

const OBFUSCATION_INDICATORS: ObfuscationIndicator[] = [
  {
    id: "OBFUSCATION_HEX_VARS",
    title: "Hexadecimal variable names (javascript-obfuscator)",
    description:
      "Code uses hex-style variable names like _0x4a3b. This is a signature of javascript-obfuscator and similar tools.",
    severity: "high",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(HEX_VARIABLE_REGEX.source, "gi");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0],
          score: 80,
        });
      }

      // Only report if we find multiple (suggests systematic obfuscation)
      return matches.length >= 3 ? matches : [];
    },
    redFlags: ["Multiple hex variables", "Combined with array rotation"],
  },
  {
    id: "OBFUSCATION_CHAR_CODE_ARRAY",
    title: "String built from char codes",
    description:
      "Code builds strings using String.fromCharCode with many numeric arguments. This hides string contents from static analysis.",
    severity: "high",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(CHAR_CODE_ARRAY_REGEX.source, "g");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0].slice(0, 80),
          score: 85,
        });
      }

      return matches;
    },
    redFlags: ["Many char codes", "Used to hide URLs or commands"],
  },
  {
    id: "OBFUSCATION_EVAL_DECODE",
    title: "eval() with decode chain",
    description:
      "Code uses eval(atob(...)) or eval(Buffer.from(...)) pattern. This executes base64-encoded code, a common malware technique.",
    severity: "critical",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(EVAL_ATOB_CHAIN_REGEX.source, "gi");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0],
          score: 95,
        });
      }

      return matches;
    },
    redFlags: ["Decodes and executes hidden code"],
  },
  {
    id: "OBFUSCATION_FUNCTION_CONSTRUCTOR",
    title: "Function constructor with string",
    description:
      "Code uses new Function('...') to create functions from strings. This is similar to eval and can execute arbitrary code.",
    severity: "high",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(FUNCTION_CONSTRUCTOR_REGEX.source, "g");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0].slice(0, 50),
          score: 85,
        });
      }

      return matches;
    },
    legitimateUses: ["Template engines", "Dynamic code generation"],
    redFlags: ["Used with encoded strings", "No clear templating purpose"],
  },
  {
    id: "OBFUSCATION_LARGE_ARRAY",
    title: "Large string array (javascript-obfuscator)",
    description:
      "Code contains a large array of strings. This is the string array technique used by javascript-obfuscator.",
    severity: "medium",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(ARRAY_ROTATION_REGEX.source, "g");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: `[${match[1]?.slice(0, 50) ?? ""}...]`,
          score: 70,
        });
      }

      return matches;
    },
    legitimateUses: ["Localization files", "Large data arrays"],
    redFlags: ["Combined with hex variables", "Strings look random"],
  },
  {
    id: "OBFUSCATION_BRACKET_CHAIN",
    title: "Excessive bracket notation property access",
    description:
      "Code uses bracket notation chains like obj['a']['b']['c']['d']. This is used to hide method calls from static analysis.",
    severity: "medium",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(BRACKET_PROPERTY_CHAIN_REGEX.source, "g");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0].slice(0, 60),
          score: 65,
        });
      }

      return matches;
    },
    legitimateUses: ["Dynamic property access"],
    redFlags: ["Long chains", "Combined with obfuscated strings"],
  },
  {
    id: "OBFUSCATION_ESCAPE_SEQUENCES",
    title: "Heavy use of hex escape sequences",
    description:
      "Code contains many consecutive \\xNN escape sequences. This hides string contents from human review.",
    severity: "medium",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(ESCAPE_SEQUENCE_HEAVY_REGEX.source, "gi");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0].slice(0, 50),
          score: 75,
        });
      }

      return matches;
    },
    redFlags: ["Long escape sequences", "Used for URLs or commands"],
  },
  {
    id: "OBFUSCATION_DECIMAL_ARRAY",
    title: "Large decimal byte array",
    description:
      "Code contains a large array of decimal numbers that could be encoded data or code.",
    severity: "medium",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regex = new RegExp(DECIMAL_ARRAY_REGEX.source, "g");
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        matches.push({
          index: match.index,
          matched: match[0].slice(0, 50) + "...",
          score: 60,
        });
      }

      return matches;
    },
    legitimateUses: ["Binary data", "Image data", "Cryptographic constants"],
    redFlags: ["Used with Buffer.from or fromCharCode"],
  },
  {
    id: "OBFUSCATION_HIGH_ENTROPY",
    title: "High entropy code region",
    description:
      "Code region has unusually high Shannon entropy (randomness). This often indicates obfuscated or encoded content.",
    severity: "medium",
    detect: (content) => {
      const matches: ObfuscationMatch[] = [];
      const regions = findHighEntropyRegions(content);

      for (const region of regions) {
        matches.push({
          index: region.start,
          matched: `Entropy: ${region.entropy.toFixed(2)} bits/char`,
          score: Math.min(90, Math.floor(region.entropy * 15)),
        });
      }

      return matches;
    },
    legitimateUses: ["Compressed data", "Base64 content", "Hash strings"],
    redFlags: ["Near eval/Function", "Large continuous regions"],
  },
];

// Indicators that should still fire on bundled code (true obfuscation)
const ALWAYS_REPORT = new Set([
  "OBFUSCATION_HEX_VARS", // _0x... is never from bundlers
  "OBFUSCATION_EVAL_DECODE", // eval(atob(...)) is never legitimate
  "OBFUSCATION_CHAR_CODE_ARRAY", // long fromCharCode chains
]);

export function checkObfuscation(contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const seenFindings = new Set<string>();

  for (const [filename, buffer] of contents.files) {
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const content = buffer.toString("utf8");

    // Detect bundled/minified code
    const bundlerInfo = detectBundler(content, filename);

    // For bundled code, only report genuine obfuscation patterns
    // Skip: high entropy, large arrays, escape sequences (normal in bundled code)
    const skipNonCritical = bundlerInfo.isBundled && !hasGenuineObfuscation(content);

    for (const indicator of OBFUSCATION_INDICATORS) {
      // Skip non-critical indicators for bundled code
      if (skipNonCritical && !ALWAYS_REPORT.has(indicator.id)) {
        continue;
      }

      const matches = indicator.detect(content);
      if (matches.length === 0) continue;

      // One finding per indicator per file
      const key = `${indicator.id}:${filename}`;
      if (seenFindings.has(key)) continue;
      seenFindings.add(key);

      const firstMatch = matches[0];
      if (!firstMatch) continue;

      findings.push({
        id: indicator.id,
        title: indicator.title,
        description: indicator.description,
        severity: indicator.severity,
        category: "obfuscation",
        location: {
          file: filename,
          line: findLineNumberByIndex(content, firstMatch.index),
        },
        metadata: {
          matchCount: matches.length,
          matched: firstMatch.matched,
          obfuscationScore: Math.max(...matches.map((m) => m.score)),
          bundled: bundlerInfo.isBundled,
          bundler: bundlerInfo.bundler,
          ...(indicator.legitimateUses && {
            legitimateUses: indicator.legitimateUses,
          }),
          ...(indicator.redFlags && { redFlags: indicator.redFlags }),
        },
      });
    }
  }

  return findings;
}
