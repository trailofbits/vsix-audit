import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { createYaraOutputReader } from "#internal/scanner/checks/yara-output.js";

function read(chunks: Buffer[]): { records: unknown[]; errors: unknown[] } {
  const records: unknown[] = [];
  const errors: unknown[] = [];
  const reader = createYaraOutputReader(
    (value) => {
      records.push(value);
    },
    (error) => {
      errors.push(error);
    },
  );
  for (const chunk of chunks) reader.write(chunk);
  reader.end();
  return { records, errors };
}

describe("streamed YARA records", () => {
  it("retains metadata and the earliest 20 matches while counting discarded occurrences", () => {
    const strings = Array.from({ length: 1000 }, (_, index) => ({
      identifier: "$a",
      offset: 1000 - index,
      match: "sentinel",
    }));
    const record = {
      path: "/file",
      rules: [{ identifier: "Rule", meta: [["severity", "high"]], strings }],
    };
    const result = read([Buffer.from(JSON.stringify(record))]);
    expect(result.errors).toEqual([]);
    expect(result.records).toEqual([
      {
        ...record,
        rules: [
          {
            ...record.rules[0],
            strings: strings.slice(-20).toReversed(),
            totalMatches: 1000,
            evidenceMaxOffset: 1000,
          },
        ],
      },
    ]);
  });

  it("retains malformed evidence after the capture limit as a diagnostic", () => {
    const strings: unknown[] = Array.from({ length: 30 }, (_, offset) => ({
      identifier: "$a",
      offset,
      match: "s",
    }));
    strings.push({ identifier: "$bad", offset: -1, match: "s" });
    const result = read([Buffer.from(JSON.stringify({ path: "/file", rules: [{ strings }] }))]);
    expect(result.errors).toEqual([]);
    expect(result.records).toMatchObject([
      {
        rules: [
          {
            totalMatches: 31,
            evidenceMaxOffset: 29,
            evidenceError: "Error: YARA-X string offset is outside the scanned file.",
          },
        ],
      },
    ]);
  });

  it.each(["{", '{"path":"x",}', "invalid", "[1,]"])(
    "reports malformed and truncated JSON: %s",
    (text) => {
      expect(read([Buffer.from(text)]).errors).toHaveLength(1);
    },
  );

  it("continues after a malformed line while retaining records on both sides", () => {
    const result = read([Buffer.from('{"path":"before"}\ninvalid\n{"path":"after"}\n')]);
    expect(result.records).toEqual([{ path: "before" }, { path: "after" }]);
    expect(result.errors).toHaveLength(1);
  });

  it("rejects a trailing comma after streamed match values have been released", () => {
    const match = JSON.stringify({ identifier: "$a", offset: 0, match: "s" });
    const text = '{"rules":[{"strings":[' + `${match},`.repeat(30) + "]}]}";
    const result = read([Buffer.from(text)]);
    expect(result.records).toEqual([]);
    expect(result.errors).toHaveLength(1);
  });

  it("keeps invalid record and evidence shapes for the module's validation", () => {
    const records = [
      null,
      { path: "x", rules: 42 },
      { path: "x", rules: [null, {}, { strings: {} }] },
    ];
    const result = read([Buffer.from(records.map((value) => JSON.stringify(value)).join("\n"))]);
    expect(result.records).toEqual(records);
    expect(result.errors).toEqual([]);
  });

  it("preserves Unicode across single-byte chunks and accepts CRLF records", () => {
    const value = {
      path: "雪🦀\n.js",
      rules: [
        {
          strings: [
            {
              identifier: "$a",
              offset: 0,
              match: "café\t🦀",
            },
          ],
        },
      ],
    };
    const bytes = Buffer.from(`${JSON.stringify(value)} \r\n`);
    const chunks = Array.from(bytes, (_, index) => bytes.subarray(index, index + 1));
    expect(read(chunks)).toEqual({
      records: [
        { ...value, rules: [{ ...value.rules[0], totalMatches: 1, evidenceMaxOffset: 0 }] },
      ],
      errors: [],
    });
  });

  it("preserves JSON values across arbitrary byte boundaries and Unicode strings", () => {
    fc.assert(
      fc.property(
        fc.jsonValue(),
        fc.array(fc.integer({ min: 1, max: 32 }), {
          minLength: 1,
          maxLength: 15,
        }),
        (value, sizes) => {
          const record = { payload: value };
          const bytes = Buffer.from(JSON.stringify(record));
          const expected: unknown = JSON.parse(bytes.toString("utf8"));
          const chunks: Buffer[] = [];
          let offset = 0;
          let step = 0;
          while (offset < bytes.length) {
            const size = sizes[step % sizes.length] ?? 1;
            chunks.push(bytes.subarray(offset, offset + size));
            offset += size;
            step++;
          }
          expect(read(chunks)).toEqual({ records: [expected], errors: [] });
        },
      ),
      { examples: [[-0, [1]]] },
    );
  });
});
