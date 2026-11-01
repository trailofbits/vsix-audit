import { describe, expect, it } from "vitest";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { makeContents } from "#internal/test-support/fixtures.js";

describe("observed argument values", () => {
  it.each([
    ["null", { kind: "literal", value: null }],
    ["false", { kind: "literal", value: false }],
    ["42.5", { kind: "literal", value: 42.5 }],
    ["`https://example.invalid`", { kind: "literal", value: "https://example.invalid" }],
    ["[]", { kind: "array", items: [] }],
    ["{}", { kind: "object", properties: {} }],
    [
      '{method: "POST"}',
      { kind: "object", properties: { method: { kind: "literal", value: "POST" } } },
    ],
  ])("retains literal syntax as data: %s", (expression, expected) => {
    const result = checkAST(makeContents({ "main.js": `fetch(${expression});` }));
    expect(result.observations?.[0]?.arguments).toEqual([expected]);
  });

  it.each([
    "endpoint",
    "1e999",
    "/pattern/",
    "10n",
    "[,1]",
    "{...options}",
    "{get method(){return value;}}",
    "`https://${host}/`",
  ])("leaves expressions unresolved instead of inventing JSON values: %s", (expression) => {
    const result = checkAST(makeContents({ "main.js": `fetch(${expression});` }));
    expect(result.observations?.[0]?.arguments).toEqual([{ kind: "unresolved", expression }]);
  });

  it.each([4096, 4097])("accounts for a literal of %s characters", (length) => {
    const value = "a".repeat(length);
    const expression = JSON.stringify(value);
    const result = checkAST(makeContents({ "main.js": `fetch(${expression});` }));
    const expected =
      length === 4096
        ? { kind: "literal", value }
        : { kind: "unresolved", expression: expression.slice(0, 200) };
    expect(result.observations?.[0]?.arguments).toEqual([expected]);
    expect(result.observations?.[0]?.location.end).toBe(expression.length + 7);
    expect(result.observations?.[0]?.snippet).toHaveLength(200);
  });

  it.each([64, 65])("accounts for an argument array with %s entries", (length) => {
    const expression = `[${Array.from({ length }, () => "1").join(",")}]`;
    const result = checkAST(makeContents({ "main.js": `fetch(${expression});` }));
    const expected =
      length === 64
        ? { kind: "array", items: Array.from({ length }, () => ({ kind: "literal", value: 1 })) }
        : { kind: "unresolved", expression };
    expect(result.observations?.[0]?.arguments).toEqual([expected]);
  });

  it("bounds nesting with an explicit unresolved inner expression", () => {
    const result = checkAST(
      makeContents({ "main.js": `fetch(${"[".repeat(9)}1${"]".repeat(9)});` }),
    );
    let value = result.observations?.[0]?.arguments[0];
    for (let depth = 0; depth < 8; depth++) {
      expect(value?.kind).toBe("array");
      value = value?.kind === "array" ? value.items[0] : undefined;
    }
    expect(value).toEqual({ kind: "unresolved", expression: "[1]" });
  });

  it("preserves prototype-shaped keys without changing object prototypes", () => {
    const result = checkAST(makeContents({ "main.js": 'fetch({"__proto__": "data"});' }));
    const value = result.observations?.[0]?.arguments[0];
    const serialized = JSON.parse(JSON.stringify(value)) as unknown;
    expect(serialized).toEqual(
      JSON.parse(
        '{"kind":"object","properties":{"__proto__":{"kind":"literal","value":"data"}}}',
      ) as unknown,
    );
  });
});
