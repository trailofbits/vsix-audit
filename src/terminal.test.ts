import fc from "fast-check";
import { afterEach, describe, expect, it, vi } from "vitest";
import { printError, reportJson, terminalText } from "#internal/terminal.js";

afterEach(() => vi.restoreAllMocks());

describe("terminal text", () => {
  it.each([
    ["\x1b[2J\x1b[H", "\\x1b[2J\\x1b[H"],
    ["\x1b[8mhidden", "\\x1b[8mhidden"],
    ["\x9b2J", "\\x9b2J"],
    ["\r\n\b\t\0\x7f", "\\x0d\\x0a\\x08\\x09\\x00\\x7f"],
    ["\u202eabc\u2069", "\\u202eabc\\u2069"],
    ["\x1b]8;;https://example.invalid\x07link", "\\x1b]8;;https://example.invalid\\x07link"],
    ["雪 🦀 café", "雪 🦀 café"],
  ])("escapes untrusted text %j", (input, expected) => {
    expect(terminalText(input)).toBe(expected);
  });

  it("never emits terminal or direction controls for arbitrary UTF-16 inputs", () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 0, max: 0xffff }), { maxLength: 100 }), (codes) => {
        const input = String.fromCharCode(...codes);
        const text = terminalText(input);
        expect(text).not.toMatch(/[\p{Cc}\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u);
        expect(terminalText(text)).toBe(text);
      }),
    );
  });

  it.each([new Error("bad\x1b[8m\rpath"), "bad\x1b[8m\rpath"])(
    "escapes Error and non-Error failures",
    (error) => {
      const log = vi.spyOn(console, "error").mockImplementation(() => {});
      printError(error);
      expect(log).toHaveBeenCalledWith("Error:", "bad\\x1b[8m\\x0dpath");
    },
  );
});

describe("machine reports", () => {
  it("escapes C1 and direction controls while retaining the exact data", () => {
    const value = { name: "bad\x9b2J\u202e\u2028\x1b[8m", nested: ["\x7f\n\t\r"] };
    const output = reportJson(value);
    expect(output).not.toMatch(/[\u007f-\u009f\u2028-\u202e]/);
    expect(JSON.parse(output)).toEqual(value);
  });

  it("preserves JSON semantics and escapes controls for arbitrary reports", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const output = reportJson({ value });
        const expected: unknown = JSON.parse(JSON.stringify({ value }));
        expect(JSON.parse(output) as unknown).toEqual(expected);
        expect(output).not.toMatch(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/);
      }),
      { examples: [[-0], [[[-0]]]] },
    );
  });
});
