import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { evidenceLocation, readStringMatches } from "#internal/scanner/checks/yara-evidence.js";

const buffer = Buffer.from("sentinel");

describe("YARA-X string evidence parser", () => {
  it.each([undefined, []])("accepts matches without strings: %j", (value) => {
    expect(readStringMatches(value, buffer)).toEqual([]);
  });

  it.each([
    null,
    42,
    {},
    [null],
    [42],
    [{}],
    [{ identifier: "$a", offset: 0 }],
    [{ identifier: 1, match: "s", offset: 0 }],
    [{ identifier: "$a", match: 42, offset: 0 }],
    [{ identifier: "$a", match: "s", offset: -1 }],
    [{ identifier: "$a", match: "s", offset: 9 }],
    [{ identifier: "$a", match: "s", offset: "0" }],
    [{ identifier: "$a", match: "s", offset: 0.5 }],
    [{ identifier: "$a", match: "s", offset: NaN }],
    [{ identifier: "$a", match: "s", offset: Infinity }],
  ])("rejects malformed evidence: %j", (value) => {
    expect(() => readStringMatches(value, buffer)).toThrow(/YARA-X/);
  });

  it("retains zero, EOF, escaped bytes, and the pattern identifier", () => {
    const value = [
      { identifier: "$a", match: "\\x00\\xff", offset: 0 },
      { identifier: "$empty", match: "", offset: buffer.length },
    ];
    expect(readStringMatches(value, buffer)).toEqual(value);
  });

  it("accepts only in-bounds integer offsets across arbitrary JSON input", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (offset) => {
        const value = [{ identifier: "$a", match: "s", offset }];
        const valid =
          typeof offset === "number" &&
          Number.isInteger(offset) &&
          offset >= 0 &&
          offset <= buffer.length;
        let accepted = true;
        try {
          readStringMatches(value, buffer);
        } catch {
          accepted = false;
        }
        expect(accepted).toBe(valid);
      }),
    );
  });
});

describe("YARA-X evidence positions", () => {
  it("keeps file-only locations for rules with no string matches", () => {
    expect(evidenceLocation("main.js", [], buffer)).toEqual({ file: "main.js" });
  });

  it.each([Buffer.from([0xff]), Buffer.from([0, 65])])(
    "uses byte positions for binary data",
    (input) => {
      expect(
        evidenceLocation("payload", [{ identifier: "$a", offset: 0, match: "bytes" }], input),
      ).toEqual({ file: "payload", byteOffset: 0 });
    },
  );

  it("does not invent text coordinates inside a UTF-8 sequence", () => {
    expect(
      evidenceLocation(
        "main.js",
        [{ identifier: "$a", offset: 1, match: "byte" }],
        Buffer.from("雪"),
      ),
    ).toEqual({ file: "main.js", byteOffset: 1 });
  });

  it("uses the earliest match even when pattern order differs from byte order", () => {
    const matches = [
      { identifier: "$later", offset: 7, match: "l" },
      { identifier: "$first", offset: 0, match: "s" },
    ];
    expect(evidenceLocation("main.js", matches, buffer)).toEqual({
      file: "main.js",
      byteOffset: 0,
      line: 1,
      column: 1,
    });
  });

  it("maps UTF-8 byte offsets to one-based UTF-16 columns", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom("a", "雪", "🦀", "\r", "\n", "é"), { maxLength: 80 }),
        (characters) => {
          const prefix = characters.join("");
          const byteOffset = Buffer.byteLength(prefix);
          const matches = [{ identifier: "$a", offset: byteOffset, match: "sentinel" }];
          expect(evidenceLocation("main.js", matches, Buffer.from(`${prefix}sentinel`))).toEqual({
            file: "main.js",
            byteOffset,
            line: prefix.split("\n").length,
            column: prefix.slice(prefix.lastIndexOf("\n") + 1).length + 1,
          });
        },
      ),
    );
  });
});
