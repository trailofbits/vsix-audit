import { RegExpParser, visitRegExpAST } from "@eslint-community/regexpp";
import { parseSync, Visitor } from "oxc-parser";
import type { Program } from "oxc-parser";
import { regexStrings } from "#internal/scanner/checks/regex-strings.js";

function patternRangeOffsets(pattern: string, flags: string): Set<number> {
  const offsets = new Set<number>();
  try {
    const parser = new RegExpParser();
    parser.parseFlags(flags);
    const parsed = parser.parsePattern(pattern, 0, pattern.length, {
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

function constructorRangeOffsets(program: Program, content: string): Set<number> {
  const offsets = new Set<number>();
  const blocked = new Set<number>();
  for (const { pattern, flags, origins, flagOrigins } of regexStrings(program, content)) {
    const ranges = flags === undefined ? new Set<number>() : patternRangeOffsets(pattern, flags);
    for (const [index, source] of origins) {
      if (ranges.has(index)) offsets.add(source);
      else blocked.add(source);
    }
    for (const source of flagOrigins) blocked.add(source);
  }
  for (const source of blocked) offsets.delete(source);
  return offsets;
}

function parsedRangeOffsets(program: Program, content: string): Set<number> {
  const offsets = constructorRangeOffsets(program, content);
  new Visitor({
    Literal(node): void {
      if (!("regex" in node)) return;
      for (const index of patternRangeOffsets(node.regex.pattern, node.regex.flags)) {
        offsets.add(node.start + 1 + index);
      }
    },
  }).visit(program);
  return offsets;
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
 * Locate embeddings used as range endpoints in regex literals or static RegExp constructions.
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
    return parsedRangeOffsets(parsed.program, content);
  } catch (error) {
    warnRangeFailure(filename, error);
    return new Set<number>();
  }
}
