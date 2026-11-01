import { RegExpParser, visitRegExpAST } from "@eslint-community/regexpp";
import { parseSync, Visitor } from "oxc-parser";
import { createHash } from "node:crypto";
import type { Program } from "oxc-parser";

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

function parsedRangeOffsets(program: Program): Set<number> {
  const offsets = new Set<number>();
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

function sourceLanguage(filename: string): "js" | "jsx" | "ts" | "tsx" {
  const extension = filename.slice(filename.lastIndexOf(".") + 1).toLowerCase();
  if (extension === "jsx" || extension === "tsx") return extension;
  return extension.endsWith("ts") ? "ts" : "js";
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
 * Locate embeddings in regex literal ranges or the hash-pinned KaTeX lexer occurrence.
 *
 * Hashes cover original file bytes; offsets refer to the decoded UTF-16 source.
 * Only U+202A can be exempted. Other strings and invalid source retain all alerts.
 * Unexpected parser or traversal failures emit a diagnostic and retain all alerts.
 */
export function findLtrRangeOffsets(source: Buffer, filename: string): Set<number> {
  const offsets = new Set<number>();
  if (!source.includes("\u202a") || !/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(filename)) return offsets;
  const content = source.toString("utf8");
  // Markdown All in One 3.6.3, dist/node/main.js. See fixtures/README.md for provenance.
  const katexOffset = 383_378;
  const katexSourceHash = "9e351182a9d98bf1b3ba0b4bf5a08658e15147d4bd55596e8bf30b549145151b";
  if (
    createHash("sha256").update(source).digest("hex") === katexSourceHash &&
    content.charCodeAt(katexOffset) === 0x202a
  ) {
    return new Set([katexOffset]);
  }
  try {
    const parsed = parseSync(filename, content, {
      lang: sourceLanguage(filename),
      sourceType: "unambiguous",
      showSemanticErrors: true,
    });
    if (parsed.errors.length !== 0) return offsets;
    return parsedRangeOffsets(parsed.program);
  } catch (error) {
    warnRangeFailure(filename, error);
    return new Set<number>();
  }
}
