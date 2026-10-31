import { RegExpParser, visitRegExpAST } from "@eslint-community/regexpp";
import { parseSync, Visitor } from "oxc-parser";
import type { RegExpLiteral, StringLiteral } from "oxc-parser";

const LTR_EMBEDDING = /\u202a/g;

function patternRangeOffsets(pattern: string, flags: string): Set<number> {
  const offsets = new Set<number>();
  try {
    const parsed = new RegExpParser().parsePattern(pattern, 0, pattern.length, {
      unicode: flags.includes("u"),
      unicodeSets: flags.includes("v"),
    });
    visitRegExpAST(parsed, {
      onCharacterClassRangeEnter(range): void {
        for (const endpoint of [range.min, range.max]) {
          const literalOffset = endpoint.raw.indexOf("\u202a");
          if (endpoint.value === 0x202a && literalOffset !== -1) {
            offsets.add(endpoint.start + literalOffset);
          }
        }
      },
    });
    return offsets;
  } catch (error) {
    if (error instanceof SyntaxError) return new Set<number>();
    throw error;
  }
}

function collectRangeOffsets(
  pattern: string,
  start: number,
  offsets: Set<number>,
  flags: readonly string[],
): void {
  if (!pattern.includes("\u202a")) return;
  for (const mode of flags) {
    for (const offset of patternRangeOffsets(pattern, mode)) offsets.add(start + offset);
  }
}

function findClassEnd(pattern: string, start: number, nested: boolean): number {
  let depth = 1;
  for (let i = start + 1; i < pattern.length; i++) {
    const character = pattern.charAt(i);
    if (character === "\\") {
      i++;
      continue;
    }
    if (character === "[" && nested) depth++;
    if (character === "]" && --depth === 0) return i;
  }
  return -1;
}

function rangeOffsets(pattern: string, flags: readonly string[]): Set<number> {
  const offsets = new Set<number>();
  for (let i = 0; i < pattern.length; i++) {
    if (pattern.charAt(i) === "\\") {
      i++;
      continue;
    }
    if (pattern.charAt(i) !== "[") continue;
    const end = findClassEnd(pattern, i, flags.includes("v"));
    if (end === -1) break;
    collectRangeOffsets(pattern.slice(i, end + 1), i, offsets, flags);
    i = end;
  }
  return offsets;
}

function stringRangeOffsets(node: StringLiteral, content: string): number[] {
  const raw = content.slice(node.start + 1, node.end - 1);
  const sourceMatches = Array.from(raw.matchAll(LTR_EMBEDDING));
  const valueMatches = Array.from(node.value.matchAll(LTR_EMBEDDING));
  if (sourceMatches.length !== valueMatches.length) return [];
  const allowed = rangeOffsets(node.value, ["u", ""]);
  for (const offset of rangeOffsets(node.value, ["v"])) allowed.add(offset);
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
    return Array.from(
      patternRangeOffsets(node.regex.pattern, node.regex.flags),
      (index) => node.start + 1 + index,
    );
  }
  return stringRangeOffsets(node, content);
}

function warnRangeFailure(filename: string, error: unknown): void {
  const reason = error instanceof Error ? error.message : String(error);
  process.emitWarning(
    `BIDI range analysis failed for ${JSON.stringify(filename)}: ${reason}. ` +
      "Directional controls remain reportable; inspect or repair the source.",
    { code: "BIDI_RANGE_ANALYSIS_FAILED" },
  );
}

/**
 * Locate embeddings used as regex range endpoints in JS/TS string or regex literals.
 *
 * Only U+202A can be exempted. Invalid or ambiguous source retains all alerts.
 * Unexpected parser or traversal failures emit a diagnostic and retain all alerts.
 */
export function findLtrRangeOffsets(content: string, filename: string): Set<number> {
  const offsets = new Set<number>();
  if (!content.includes("\u202a") || !/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(filename)) return offsets;
  const extension = filename.slice(filename.lastIndexOf(".") + 1).toLowerCase();
  const lang =
    extension === "jsx" || extension === "tsx" ? extension : extension.endsWith("ts") ? "ts" : "js";
  try {
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
  } catch (error) {
    warnRangeFailure(filename, error);
    return new Set<number>();
  }
}
