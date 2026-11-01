import { JSONParser, type ParsedElementInfo } from "@streamparser/json";
import { readStringMatch } from "#internal/scanner/checks/yara-evidence.js";
import type { YaraStringMatch } from "#internal/scanner/types.js";

interface CapturedEvidence {
  matches: YaraStringMatch[];
  total: number;
  maxOffset: number;
  error?: string;
}

export interface YaraOutputReader {
  write(chunk: Buffer): void;
  end(): void;
}

function captureMatch(capture: CapturedEvidence, value: unknown): void {
  capture.total++;
  try {
    const match = readStringMatch(value, Number.MAX_SAFE_INTEGER);
    capture.maxOffset = Math.max(capture.maxOffset, match.offset);
    const last = capture.matches.at(-1)?.offset ?? Infinity;
    if (capture.matches.length >= 20 && match.offset >= last) return;
    capture.matches.push(match);
    capture.matches.sort((a, b) => a.offset - b.offset);
    capture.matches.length = Math.min(capture.matches.length, 20);
  } catch (error) {
    capture.error = String(error);
  }
}

function restoreRule(rule: unknown, captures: WeakMap<object, CapturedEvidence>): void {
  if (typeof rule !== "object" || rule === null || !("strings" in rule)) return;
  if (!Array.isArray(rule.strings)) return;
  const capture = captures.get(rule.strings);
  if (capture === undefined) return;
  Object.assign(rule, {
    strings: capture.matches,
    totalMatches: capture.total,
    evidenceMaxOffset: capture.maxOffset,
    ...(capture.error === undefined ? {} : { evidenceError: capture.error }),
  });
}

function restoreEvidence(value: unknown, captures: WeakMap<object, CapturedEvidence>): void {
  if (typeof value !== "object" || value === null || !("rules" in value)) return;
  if (!Array.isArray(value.rules)) return;
  for (const rule of value.rules as unknown[]) restoreRule(rule, captures);
}

function recordParser(onRecord: (value: unknown) => void): JSONParser {
  const captures = new WeakMap<object, CapturedEvidence>();
  const parser = new JSONParser({ paths: ["$", "$.rules.*.strings.*"], keepStack: false });
  parser.onValue = (entry: ParsedElementInfo): void => {
    if (entry.stack.length === 0) {
      restoreEvidence(entry.value, captures);
      onRecord(entry.value);
      return;
    }
    if (!Array.isArray(entry.parent)) return;
    let capture = captures.get(entry.parent);
    if (capture === undefined) {
      capture = { matches: [], total: 0, maxOffset: 0 };
      captures.set(entry.parent, capture);
    }
    captureMatch(capture, entry.value);
    // The parser tracks array membership separately, so emitted matches can be released.
    entry.parent.length = 0;
  };
  return parser;
}

/**
 * Read NDJSON incrementally, retaining at most 20 string matches per rule and recovering by line.
 */
export function createYaraOutputReader(
  onRecord: (value: unknown) => void,
  onError: (error: unknown) => void,
): YaraOutputReader {
  let parser: JSONParser | undefined;
  let failed = false;
  function feed(chunk: Buffer): void {
    if (chunk.length === 0 || failed) return;
    parser ??= recordParser(onRecord);
    try {
      parser.write(chunk);
    } catch (error) {
      failed = true;
      onError(error);
    }
  }
  function end(): void {
    try {
      if (parser !== undefined && !failed && !parser.isEnded) parser.end();
    } catch (error) {
      onError(error);
    }
    parser = undefined;
    failed = false;
  }
  return {
    write: (chunk) => {
      let start = 0;
      for (let index = chunk.indexOf(0x0a); index !== -1; index = chunk.indexOf(0x0a, start)) {
        feed(chunk.subarray(start, index));
        end();
        start = index + 1;
      }
      feed(chunk.subarray(start));
    },
    end,
  };
}
