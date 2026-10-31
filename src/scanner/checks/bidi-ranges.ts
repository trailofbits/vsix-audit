import { parseSync, Visitor } from "oxc-parser";
import type { RegExpLiteral, StringLiteral } from "oxc-parser";

const LTR_EMBEDDING = /\u202a/g;

function isEscaped(pattern: string, index: number): boolean {
  let backslashes = 0;
  for (let i = index - 1; i >= 0 && pattern[i] === "\\"; i--) backslashes++;
  return backslashes % 2 === 1;
}

function isRangeEndpoint(pattern: string, index: number): boolean {
  const firstMember = pattern[1] === "^" ? 2 : 1;
  const before = index - 1;
  const after = index + 1;
  return (
    (pattern[before] === "-" && before > firstMember && !isEscaped(pattern, before)) ||
    (pattern[after] === "-" && after < pattern.length - 2)
  );
}

function isUnicodeClass(pattern: string): boolean {
  try {
    return new RegExp(pattern, "u").unicode;
  } catch (error) {
    if (error instanceof SyntaxError) return false;
    throw error;
  }
}

function collectRangeOffsets(pattern: string, start: number, offsets: Set<number>): void {
  if (!pattern.includes("\u202a") || !isUnicodeClass(pattern)) return;
  for (const match of pattern.matchAll(LTR_EMBEDDING)) {
    if (isRangeEndpoint(pattern, match.index)) offsets.add(start + match.index);
  }
}

function rangeOffsets(pattern: string): Set<number> {
  const offsets = new Set<number>();
  let start = -1;
  for (let i = 0; i < pattern.length; i++) {
    switch (pattern.charAt(i)) {
      case "\\":
        i++;
        break;
      case "[":
        if (start === -1) start = i;
        break;
      case "]":
        if (start !== -1) {
          collectRangeOffsets(pattern.slice(start, i + 1), start, offsets);
          start = -1;
        }
        break;
      default:
        break;
    }
  }
  return offsets;
}

function stringRangeOffsets(node: StringLiteral, content: string): number[] {
  const raw = content.slice(node.start + 1, node.end - 1);
  const sourceMatches = Array.from(raw.matchAll(LTR_EMBEDDING));
  const valueMatches = Array.from(node.value.matchAll(LTR_EMBEDDING));
  if (sourceMatches.length !== valueMatches.length) return [];
  const allowed = rangeOffsets(node.value);
  const offsets: number[] = [];
  for (const [index, match] of sourceMatches.entries()) {
    const valueMatch = valueMatches[index];
    if (valueMatch !== undefined && allowed.has(valueMatch.index)) {
      offsets.push(node.start + 1 + match.index);
    }
  }
  return offsets;
}

function literalRangeOffsets(node: StringLiteral | RegExpLiteral, content: string): number[] {
  if ("regex" in node) {
    return Array.from(rangeOffsets(node.regex.pattern), (index) => node.start + 1 + index);
  }
  return stringRangeOffsets(node, content);
}

/**
 * Locate left-to-right embeddings used as regex range endpoints in JS/TS literals.
 *
 * Only U+202A can be exempted. Parse errors and ambiguous escape mappings retain all alerts.
 */
export function findLtrRangeOffsets(content: string, filename: string): Set<number> {
  const offsets = new Set<number>();
  if (!content.includes("\u202a") || !/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(filename)) return offsets;
  const extension = filename.slice(filename.lastIndexOf(".") + 1).toLowerCase();
  const lang =
    extension === "jsx" || extension === "tsx" ? extension : extension.endsWith("ts") ? "ts" : "js";
  const parsed = parseSync(filename, content, {
    lang,
    sourceType: "unambiguous",
    showSemanticErrors: true,
  });
  if (parsed.errors.length !== 0) return offsets;
  new Visitor({
    Literal(node): void {
      if ("regex" in node || typeof node.value === "string") {
        for (const offset of literalRangeOffsets(node, content)) offsets.add(offset);
      }
    },
  }).visit(parsed.program);
  return offsets;
}
