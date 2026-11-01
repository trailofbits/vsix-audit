import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { afterEach, describe, expect, it } from "vitest";
import { checkAST } from "#internal/scanner/checks/ast.js";
import { scanExtension } from "#internal/scanner/index.js";
import { makeContents } from "#internal/test-support/fixtures.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const CASES = [
  {
    source: 'fetch("https://fresh.example.invalid/api", {method: "POST"});',
    kind: "network-request",
    api: "global.fetch",
    capability: "network",
    args: [
      { kind: "literal", value: "https://fresh.example.invalid/api" },
      { kind: "object", properties: { method: { kind: "literal", value: "POST" } } },
    ],
  },
  {
    source: 'import {readFileSync as read} from "node:fs"; read("/tmp/cache", "utf8");',
    kind: "file-read",
    api: "fs.readFileSync",
    capability: "fileAccess",
    args: [
      { kind: "literal", value: "/tmp/cache" },
      { kind: "literal", value: "utf8" },
    ],
  },
  {
    source: 'const fs = require("fs"); fs.writeFileSync("/tmp/cache", content);',
    kind: "file-write",
    api: "fs.writeFileSync",
    capability: "fileAccess",
    args: [
      { kind: "literal", value: "/tmp/cache" },
      { kind: "unresolved", expression: "content" },
    ],
  },
  {
    source: 'import {spawn as run} from "child_process"; run("git", ["status"]);',
    kind: "process-execution",
    api: "child_process.spawn",
    capability: "execution",
    args: [
      { kind: "literal", value: "git" },
      { kind: "array", items: [{ kind: "literal", value: "status" }] },
    ],
  },
  {
    source: 'eval("1 + 1");',
    kind: "code-execution",
    api: "global.eval",
    capability: "execution",
    args: [{ kind: "literal", value: "1 + 1" }],
  },
  {
    source:
      'import * as vscode from "vscode"; vscode.authentication.getSession("github", ["repo"]);',
    kind: "credential-access",
    api: "vscode.authentication.getSession",
    capability: "credentials",
    args: [
      { kind: "literal", value: "github" },
      { kind: "array", items: [{ kind: "literal", value: "repo" }] },
    ],
  },
] as const;

describe("source observation contract", () => {
  it.each(CASES)("records $kind independently of suspiciousness", (test) => {
    const result = checkAST(makeContents({ "main.js": test.source }));
    expect(result.observations).toContainEqual(
      expect.objectContaining({
        kind: test.kind,
        api: test.api,
        capability: test.capability,
        evidence: "call",
        arguments: test.args,
        location: expect.objectContaining({ file: "main.js", line: 1 }) as unknown,
      }),
    );
    expect(result.warnings).toEqual([]);
  });

  it.each([
    'const docs = {browser: "Firefox", storage: "IndexedDB", api: "readFileSync"};',
    "const calculator = {eval(value) {return value;}}; calculator.eval(payload);",
    'function work(fetch) { fetch("https://example.invalid"); }',
    'fetch("example"); function fetch(value) {return value;}',
    'import * as fs from "fs"; function work(fs) {fs.readFileSync("example");}',
    '// fetch("https://example.invalid");\nconst doc = "fs.readFileSync()";',
    'let send = fetch; send = local; send("https://example.invalid");',
    'const send = fetch; ({send} = other); send("https://example.invalid");',
    'globalThis.fetch = local; fetch("https://example.invalid");',
    "const Calculator = class fetch { run() {fetch(url);} };",
    'try {work();} catch (fetch) {fetch("https://example.invalid");}',
    'function work() {fetch("example"); {var fetch = local;}}',
  ])("does not turn unrelated references or shadowed names into API calls: %s", (source) => {
    const result = checkAST(makeContents({ "main.js": source }));
    expect(result.observations?.filter((item) => item.evidence === "call")).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  it.each([
    [
      'const {readFileSync: read} = require("node:fs"); read(path);',
      "file-read",
      "fs.readFileSync",
    ],
    ['import fs from "node:fs/promises"; fs.readFile(path);', "file-read", "fs/promises.readFile"],
    [
      'const fs = require("fs"); fs.promises.writeFile(path, data);',
      "file-write",
      "fs.promises.writeFile",
    ],
    ['import * as fs from "fs"; fs["readFileSync"](path);', "file-read", "fs.readFileSync"],
    ["const request = globalThis.fetch; request(url);", "network-request", "global.fetch"],
    [
      "const send = fetch; function work(){const send=local; send(url);} send(url);",
      "network-request",
      "global.fetch",
    ],
    ['const fs = require("fs"); fs[operation](path);', "dynamic-call", "fs.*"],
    ['import https from "node:https"; https.get(url);', "network-request", "https.get"],
    ['import axios from "axios"; axios.post(url);', "network-request", "axios.post"],
    ["new WebSocket(url);", "network-client", "global.WebSocket"],
  ])("resolves common module and scope variants: %s", (source, kind, api) => {
    const calls = checkAST(makeContents({ "main.js": source })).observations?.filter(
      (item) => item.kind === kind,
    );
    expect(calls).toMatchObject([{ kind, api, evidence: "call" }]);
  });

  it("inspects extension code without activating it", async () => {
    const root = await mkdtemp(join(tmpdir(), "vsix-never-execute-"));
    roots.push(root);
    const sentinel = join(root, "executed");
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0", main: "main.js" }),
    );
    await writeFile(
      join(root, "main.js"),
      `require("fs").writeFileSync(${JSON.stringify(sentinel)}, "executed");`,
    );
    const result = await scanExtension(root, {
      output: "json",
      severity: "critical",
      modules: ["ast"],
    });
    expect(result.observations).toContainEqual(expect.objectContaining({ kind: "file-write" }));
    expect(existsSync(sentinel)).toBe(false);
  });

  it("preserves both operations on one line and their exact source spans", () => {
    const source = 'const emoji = "😀"; eval(first); eval(second);';
    const result = checkAST(makeContents({ "min.js": source }));
    expect(result.observations).toHaveLength(2);
    expect(result.findings.filter((finding) => finding.id === "AST_EVAL_DYNAMIC")).toHaveLength(2);
    expect(
      result.observations?.map((item) => source.slice(item.location.start, item.location.end)),
    ).toEqual(["eval(first)", "eval(second)"]);
    expect(result.observations?.map((item) => item.location.column)).toEqual([
      source.indexOf("eval(first)") + 1,
      source.indexOf("eval(second)") + 1,
    ]);
  });

  it("retains unresolved targets instead of guessing their value", () => {
    const result = checkAST(makeContents({ "main.js": "fetch(endpoint); require(moduleName);" }));
    expect(result.observations).toMatchObject([
      { kind: "network-request", arguments: [{ kind: "unresolved", expression: "endpoint" }] },
      { kind: "module-load", arguments: [{ kind: "unresolved", expression: "moduleName" }] },
    ]);
  });

  it("recognizes fresh destinations and aliases without indicator lists", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 1_000_000 }), (suffix) => {
        const target = `https://fresh-${suffix}.example.invalid/api`;
        const source = `const send = fetch; send(${JSON.stringify(target)});`;
        const result = checkAST(makeContents({ "vendor/chunk.min.js": source }));
        expect(result.observations).toMatchObject([
          {
            kind: "network-request",
            api: "global.fetch",
            arguments: [{ kind: "literal", value: target }],
          },
        ]);
      }),
      { numRuns: 30 },
    );
  });

  it("preserves observations across severity and intelligence settings", async () => {
    const root = await mkdtemp(join(tmpdir(), "vsix-behavior-"));
    roots.push(root);
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0" }),
    );
    await writeFile(join(root, "main.js"), "fetch(destination); eval(payload);");
    const baseline = await scanExtension(root, {
      output: "json",
      severity: "low",
      intel: "local",
      modules: ["ast"],
    });
    const filtered = await scanExtension(root, {
      output: "json",
      severity: "critical",
      intel: "none",
      modules: ["ast"],
    });
    expect(baseline.observations).toHaveLength(2);
    expect(filtered.observations).toEqual(baseline.observations);
    expect(baseline.findings).toHaveLength(1);
    expect(filtered.findings).toEqual([]);
  });

  it("retains a large inventory without losing occurrences at argument-count limits", async () => {
    const root = await mkdtemp(join(tmpdir(), "vsix-large-inventory-"));
    roots.push(root);
    const count = 131_072;
    const call = "fetch(url);";
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ name: "fixture", version: "1.0.0" }),
    );
    await writeFile(join(root, "main.js"), call.repeat(count));
    const result = await scanExtension(root, {
      output: "json",
      severity: "critical",
      modules: ["ast"],
    });
    expect(result.observations).toHaveLength(count);
    expect(result.observations.at(-1)?.location.start).toBe((count - 1) * call.length);
    expect(result.metadata.coverage.degraded).toBe(false);
  });
});
