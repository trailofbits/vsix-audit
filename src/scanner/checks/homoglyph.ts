import { computeLineStarts, offsetToColumn, offsetToLine } from "../utils.js";

export interface UnicodeMatch {
  line: number;
  column: number;
  matched: string;
  context: string;
}

export interface SourceChar {
  sourceStart: number;
  sourceLength: number;
  decoded: string;
}

interface SourceLetterRun {
  chars: SourceChar[];
  sourceStart: number;
  sourceEnd: number;
}

export type HomoglyphRunKind = "mixed-script" | "all-lookalike-domain";

export interface HomoglyphRunMatch {
  kind: HomoglyphRunKind;
  firstHomoglyph: SourceChar;
  sourceStart: number;
  sourceEnd: number;
}

const CYRILLIC_TO_LATIN_HOMOGLYPHS: ReadonlyArray<readonly [string, string]> = [
  ["\u0430", "a"], // U+0430 CYRILLIC SMALL LETTER A
  ["\u0441", "c"], // U+0441 CYRILLIC SMALL LETTER ES
  ["\u0435", "e"], // U+0435 CYRILLIC SMALL LETTER IE
  ["\u0456", "i"], // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
  ["\u04CF", "l"], // U+04CF CYRILLIC SMALL LETTER PALOCHKA
  ["\u043E", "o"], // U+043E CYRILLIC SMALL LETTER O
  ["\u0440", "p"], // U+0440 CYRILLIC SMALL LETTER ER
  ["\u0445", "x"], // U+0445 CYRILLIC SMALL LETTER HA
  ["\u0443", "y"], // U+0443 CYRILLIC SMALL LETTER U
  ["\u0410", "A"], // U+0410 CYRILLIC CAPITAL LETTER A
  ["\u0412", "B"], // U+0412 CYRILLIC CAPITAL LETTER VE
  ["\u0421", "C"], // U+0421 CYRILLIC CAPITAL LETTER ES
  ["\u0415", "E"], // U+0415 CYRILLIC CAPITAL LETTER IE
  ["\u041D", "H"], // U+041D CYRILLIC CAPITAL LETTER EN
  ["\u0406", "I"], // U+0406 CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
  ["\u041A", "K"], // U+041A CYRILLIC CAPITAL LETTER KA
  ["\u041C", "M"], // U+041C CYRILLIC CAPITAL LETTER EM
  ["\u041E", "O"], // U+041E CYRILLIC CAPITAL LETTER O
  ["\u0420", "P"], // U+0420 CYRILLIC CAPITAL LETTER ER
  ["\u0422", "T"], // U+0422 CYRILLIC CAPITAL LETTER TE
  ["\u0425", "X"], // U+0425 CYRILLIC CAPITAL LETTER HA
];

const CYRILLIC_LOOKALIKE_SET = new Set(CYRILLIC_TO_LATIN_HOMOGLYPHS.map(([cyr]) => cyr));

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

function isAsciiLatinLetter(ch: string): boolean {
  const code = ch.codePointAt(0);
  return code !== undefined && ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a));
}

function isCyrillicLetter(ch: string): boolean {
  const code = ch.codePointAt(0);
  return code !== undefined && code >= 0x0400 && code <= 0x04ff;
}

function isTokenLetter(ch: string): boolean {
  return isAsciiLatinLetter(ch) || isCyrillicLetter(ch);
}

function hasOddBackslashPrefix(content: string, index: number): boolean {
  let count = 0;
  for (let i = index - 1; i >= 0 && content[i] === "\\"; i--) {
    count += 1;
  }
  return count % 2 === 1;
}

function decodeSourceChar(content: string, index: number): SourceChar {
  if (
    content[index] === "\\" &&
    content[index + 1] === "u" &&
    !hasOddBackslashPrefix(content, index)
  ) {
    if (content[index + 2] === "{") {
      const close = content.indexOf("}", index + 3);
      const hex = close === -1 ? "" : content.slice(index + 3, close);
      if (/^[0-9A-Fa-f]{1,6}$/.test(hex)) {
        const codePoint = parseInt(hex, 16);
        if (codePoint <= 0x10ffff) {
          return {
            sourceStart: index,
            sourceLength: close - index + 1,
            decoded: String.fromCodePoint(codePoint),
          };
        }
      }
    } else {
      const hex = content.slice(index + 2, index + 6);
      if (/^[0-9A-Fa-f]{4}$/.test(hex)) {
        return {
          sourceStart: index,
          sourceLength: 6,
          decoded: String.fromCodePoint(parseInt(hex, 16)),
        };
      }
    }
  }

  const codePoint = content.codePointAt(index) ?? content.charCodeAt(index);
  const decoded = String.fromCodePoint(codePoint);
  return {
    sourceStart: index,
    sourceLength: decoded.length,
    decoded,
  };
}

function findLetterRuns(content: string): SourceLetterRun[] {
  const runs: SourceLetterRun[] = [];
  let current: SourceChar[] = [];

  const flush = () => {
    if (current.length === 0) return;
    const first = current[0]!;
    const last = current.at(-1)!;
    runs.push({
      chars: current,
      sourceStart: first.sourceStart,
      sourceEnd: last.sourceStart + last.sourceLength,
    });
    current = [];
  };

  for (let i = 0; i < content.length; ) {
    const char = decodeSourceChar(content, i);
    if (isTokenLetter(char.decoded)) {
      current.push(char);
    } else {
      flush();
    }
    i += char.sourceLength;
  }
  flush();

  return runs;
}

function isDomainLabelContext(content: string, run: SourceLetterRun): boolean {
  if (run.chars.length < 3) return false;

  const before = content.slice(Math.max(0, run.sourceStart - 16), run.sourceStart);
  const after = content.slice(run.sourceEnd, Math.min(content.length, run.sourceEnd + 64));
  if (!/^\.[A-Za-z0-9-]{2,}\b/.test(after)) return false;

  return run.sourceStart === 0 || /(?:^|[.:/@\s"'`(<[{])$/.test(before);
}

function classifyRun(content: string, run: SourceLetterRun): HomoglyphRunMatch | null {
  let hasLatin = false;
  let firstHomoglyph: SourceChar | undefined;
  let allCyrillicLookalikes = true;

  for (const char of run.chars) {
    if (isAsciiLatinLetter(char.decoded)) {
      hasLatin = true;
      allCyrillicLookalikes = false;
    } else if (CYRILLIC_LOOKALIKE_SET.has(char.decoded)) {
      firstHomoglyph ??= char;
    } else {
      allCyrillicLookalikes = false;
    }
  }

  if (!firstHomoglyph) return null;
  if (hasLatin) {
    return {
      kind: "mixed-script",
      firstHomoglyph,
      sourceStart: run.sourceStart,
      sourceEnd: run.sourceEnd,
    };
  }
  if (allCyrillicLookalikes && isDomainLabelContext(content, run)) {
    return {
      kind: "all-lookalike-domain",
      firstHomoglyph,
      sourceStart: run.sourceStart,
      sourceEnd: run.sourceEnd,
    };
  }
  return null;
}

export function scanCyrillicHomoglyphRuns(content: string): HomoglyphRunMatch[] {
  return findLetterRuns(content)
    .map((run) => classifyRun(content, run))
    .filter((match): match is HomoglyphRunMatch => match !== null);
}

export function detectCyrillicHomoglyphs(content: string): UnicodeMatch[] {
  const starts = computeLineStarts(content);

  return scanCyrillicHomoglyphRuns(content).map((match) => {
    const { line, column } = findLineAndColumn(match.firstHomoglyph.sourceStart, starts);
    return {
      line,
      column,
      matched: match.firstHomoglyph.decoded,
      context: getContext(
        content,
        match.firstHomoglyph.sourceStart,
        match.firstHomoglyph.sourceLength,
      ),
    };
  });
}
