import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { printTextReport, toSarif } from "#internal/formatters.js";
import { hasCoverageExitFailure } from "#internal/scan-options.js";
import { checkYara, isYaraAvailable } from "#internal/scanner/checks/yara.js";
import { scanExtension } from "#internal/scanner/index.js";
import { loadZooData } from "#internal/scanner/loaders/zoo.js";
import type { ScanResult } from "#internal/scanner/types.js";
import { loadDirectory } from "#internal/scanner/vsix.js";

let root = "";
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-local-workflow-"));
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ name: "fixture", version: "1.0.0", main: "main.js" }),
  );
  await writeFile(join(root, "main.js"), "module.exports = {};");
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(root, { recursive: true, force: true });
});

describe("local coverage regressions", () => {
  it.each([".git", ".git/payload.js", "nested/.git/payload.js"])(
    "checks indicators inside %s",
    async (file) => {
      const domain = [...(await loadZooData()).domains][0];
      expect(domain).toBeDefined();
      await mkdir(join(root, file, ".."), { recursive: true });
      await writeFile(join(root, file), `module.exports = "https://${domain}";`);
      const scan = await scanExtension(root, {
        output: "json",
        severity: "critical",
        modules: ["ioc"],
      });
      const finding = scan.findings.find((entry) => entry.id === "KNOWN_C2_DOMAIN");
      expect(finding?.location?.file).toBe(file);
    },
  );

  it("checks binary indicators and reports the native analysis limit", async () => {
    const domain = [...(await loadZooData()).domains][0];
    await writeFile(
      join(root, "binding.node"),
      Buffer.concat([
        Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0xff]),
        Buffer.from(`https://${domain}\0`),
      ]),
    );
    const scan = await scanExtension(root, {
      output: "json",
      severity: "critical",
      modules: ["ioc"],
      strict: true,
    });
    expect(scan.findings).toContainEqual(expect.objectContaining({ id: "KNOWN_C2_DOMAIN" }));
    expect(scan.metadata.coverage.degraded).toBe(true);
    expect(scan.metadata.coverage.warnings.join(" ")).toMatch(/binding.node.*native/i);
    expect(
      hasCoverageExitFailure(scan, { output: "json", severity: "critical", strict: true }),
    ).toBe(true);
  });
});

function report(): ScanResult {
  return {
    observations: [],
    extension: { id: "test.fixture", name: "fixture", version: "1.0.0" },
    findings: [
      {
        id: "EXAMPLE",
        title: "Example",
        description: "Review this file.",
        category: "test",
        severity: "high",
        location: { file: "main.js", line: 2, column: 5 },
      },
    ],
    inventory: [],
    metadata: {
      scannedAt: "2026-10-31T00:00:00Z",
      scanDuration: 1,
      coverage: { degraded: false, warnings: [], incompleteModules: [] },
    },
  };
}

describe("report fidelity", () => {
  it("reports AST columns using the same one-based convention as other checks", async () => {
    const source = 'const label = "雪"; eval(code);';
    await writeFile(join(root, "main.js"), source);
    const scan = await scanExtension(root, { output: "json", severity: "low", modules: ["ast"] });
    const finding = scan.findings.find((entry) => entry.id === "AST_EVAL_DYNAMIC");
    expect(finding?.location).toEqual({
      file: "main.js",
      line: 1,
      column: source.indexOf("eval") + 1,
    });
  });
  it("retains coverage failures without findings in SARIF", () => {
    const scan = report();
    scan.findings.length = 0;
    scan.metadata.coverage = {
      degraded: true,
      warnings: ["Cannot verify repository"],
      incompleteModules: ["repository"],
    };
    const run = toSarif(scan, "test").runs[0];
    expect(run?.invocations?.[0]?.executionSuccessful).toBe(false);
    expect(run?.invocations?.[0]?.toolExecutionNotifications).toContainEqual(
      expect.objectContaining({ message: { text: "Cannot verify repository" } }),
    );
  });

  it("retains known columns in SARIF and text", () => {
    const scan = report();
    const region = toSarif(scan, "test").runs[0]?.results[0]?.locations[0]?.physicalLocation.region;
    expect(region).toEqual({ startLine: 2, startColumn: 5 });
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    printTextReport(scan);
    expect(log.mock.calls.flat().join("\n")).toContain("main.js:2:5");
  });

  it("escapes terminal controls in metadata and finding paths", () => {
    const base = report();
    const scan = {
      ...base,
      extension: { ...base.extension, name: "evil\x1b[2J\x1b[H\rPASS\x1b[8m" },
      findings: base.findings.map((finding) => ({
        ...finding,
        location: { file: "bad\x1b[8m.js" },
      })),
    };
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    printTextReport(scan);
    const text = log.mock.calls.flat().join("\n");
    expect(text).not.toContain("\x1b[2J");
    expect(text).not.toContain("\x1b[8m");
    expect(text).not.toContain("\r");
    expect(text).toContain("\\x1b[2J");
    expect(text).toContain("bad\\x1b[8m.js");
  });
});

const yaraAvailable = await isYaraAvailable();
describe("YARA evidence", () => {
  it.skipIf(!yaraAvailable)("bounds captured excerpts and preserves the match count", async () => {
    const rules = join(root, "count-rules");
    await mkdir(rules);
    await writeFile(
      join(rules, "count.yar"),
      'rule Count { meta: severity = "high" strings: $a = "sentinel" condition: $a }',
    );
    const contents = await loadDirectory(root);
    contents.files.clear();
    contents.files.set("main.js", Buffer.from("sentinel\n".repeat(30)));
    const result = await checkYara(contents, rules);
    expect(result.warnings).toEqual([]);
    expect(result.findings[0]?.metadata?.matches).toHaveLength(20);
    expect(result.findings[0]?.metadata?.totalMatches).toBe(30);
  });
  it.skipIf(!yaraAvailable)(
    "reports compiled files outside the bundled script rule scope",
    async () => {
      const rules = join(root, "binary-rules");
      await mkdir(rules);
      await writeFile(
        join(rules, "binary.yar"),
        ['rule Binary { meta: severity = "high" strings: $a = "sentinel" condition: $a }'].join(
          "\n",
        ),
      );
      const contents = await loadDirectory(root);
      contents.files.clear();
      contents.files.set("binding.node", Buffer.from([0, 0xff, ...Buffer.from("sentinel")]));
      const result = await checkYara(contents, rules);
      expect(result.warnings.join(" ")).toContain("binding.node");
      expect(result.findings).toMatchObject([{ id: "YARA_SKIPPED_BINARY" }]);
    },
  );
  it.skipIf(!yaraAvailable)("retains string offsets and correct UTF-8 text positions", async () => {
    const rules = join(root, "rules");
    await mkdir(rules);
    await writeFile(
      join(rules, "evidence.yar"),
      [
        "rule Evidence {",
        'meta: severity = "high"',
        'strings: $a = "sentinel" condition: $a }',
      ].join("\n"),
    );
    const source = "// 雪\n  sentinel();";
    await writeFile(join(root, "main.js"), source);
    const contents = await loadDirectory(root);
    contents.files.delete("rules/evidence.yar");
    const result = await checkYara(contents, rules);
    expect(result.warnings).toEqual([]);
    expect(result.findings).toMatchObject([
      {
        id: "YARA_Evidence",
        location: { file: "main.js", line: 2, column: 3, byteOffset: 9 },
        metadata: {
          matches: [{ identifier: "$a", offset: 9, match: "sentinel" }],
        },
      },
    ]);
  });
});

describe("script YARA format boundaries", () => {
  it.skipIf(!yaraAvailable).each(["payload.js", "payload"])(
    "reports a renamed executable outside YARA's script scope: %s",
    async (file) => {
      const contents = await loadDirectory(root);
      contents.files.clear();
      contents.files.set(file, Buffer.from([0x7f, 0x45, 0x4c, 0x46, ...Buffer.from("sentinel")]));
      const result = await checkYara(contents);
      expect(result.findings).toMatchObject([{ id: "YARA_SKIPPED_BINARY" }]);
      expect(result.warnings.join(" ")).toContain(file);
    },
  );

  it.skipIf(!yaraAvailable)(
    "keeps count-based rules complete when evidence exceeds 10 MiB",
    async () => {
      const rules = join(root, "large-output-rules");
      await mkdir(rules);
      await writeFile(
        join(rules, "repeat.yar"),
        'rule Repeat { meta: severity = "high" strings: $a = "sentinel" condition: #a > 200000 }',
      );
      const contents = await loadDirectory(root);
      contents.files.clear();
      contents.files.set("main.js", Buffer.from("sentinel\n".repeat(240_000)));
      const result = await checkYara(contents, rules);
      expect(result.warnings).toEqual([]);
      expect(result.findings).toMatchObject([
        {
          id: "YARA_Repeat",
          severity: "high",
          metadata: { totalMatches: 240_000 },
        },
      ]);
      expect(result.findings[0]?.metadata?.matches).toHaveLength(20);
    },
    30_000,
  );

  it.skipIf(!yaraAvailable)("does not apply script obfuscation rules to GIF data", async () => {
    const image = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");
    const comment = Buffer.from("()".repeat(40));
    const gif = Buffer.concat([
      image.subarray(0, -1),
      Buffer.from([0x21, 0xfe, comment.length]),
      comment,
      Buffer.from([0, 0x3b]),
    ]);
    const contents = await loadDirectory(root);
    contents.files.clear();
    contents.files.set("images/help.gif", gif);
    expect(await checkYara(contents)).toEqual({ findings: [], warnings: [] });
  });
});
