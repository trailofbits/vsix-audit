import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { toSarif } from "#internal/formatters.js";
import type { BatchScanResult, Observation, ScanResult } from "#internal/scanner/types.js";
import { runCli } from "#internal/test-support/cli.js";
import { createTestZip } from "#internal/test-support/zip.js";

const FIXTURE = fileURLToPath(new URL("../test-corpus/behavior/", import.meta.url));
const CONTROLS = ["--module", "ast", "--severity", "critical", "--no-threat-intel"];
const EXPECTED = [
  { kind: "module-load", api: "import", arguments: [{ kind: "literal", value: "node:fs" }] },
  {
    kind: "module-load",
    api: "import",
    arguments: [{ kind: "literal", value: "node:child_process" }],
  },
  {
    kind: "network-request",
    api: "global.fetch",
    arguments: [
      { kind: "literal", value: "https://updates.example.invalid/check" },
      { kind: "object", properties: { method: { kind: "literal", value: "GET" } } },
    ],
  },
  {
    kind: "file-read",
    api: "fs.readFileSync",
    arguments: [
      { kind: "literal", value: "/tmp/vsix-cache" },
      { kind: "literal", value: "utf8" },
    ],
  },
  {
    kind: "file-write",
    api: "fs.writeFileSync",
    arguments: [
      { kind: "literal", value: "/tmp/vsix-cache" },
      { kind: "literal", value: "value" },
    ],
  },
  {
    kind: "process-execution",
    api: "child_process.spawn",
    arguments: [
      { kind: "literal", value: "git" },
      { kind: "array", items: [{ kind: "literal", value: "status" }] },
    ],
  },
  { kind: "code-execution", api: "global.eval", arguments: [{ kind: "literal", value: "1 + 1" }] },
];
let root: string;
let directory: string;
let source: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-behavior-cli-"));
  directory = join(root, "store", "review.behavior-fixture-1.0.0");
  await mkdir(directory, { recursive: true });
  source = await readFile(join(FIXTURE, "source.txt"), "utf8");
  await cp(join(FIXTURE, "package.json"), join(directory, "package.json"));
  await writeFile(join(directory, "main.js"), source);
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function assertObservations(observations: Observation[]): void {
  expect(
    observations.map(({ kind, api, arguments: args }) => ({ kind, api, arguments: args })),
  ).toEqual(EXPECTED);
  for (const item of observations) {
    expect(item.snippet).toBe(source.slice(item.location.start, item.location.end));
    expect(item.location.file).toBe("main.js");
  }
  expect(observations[2]?.location).toMatchObject({ line: 5, column: 3, endLine: 5 });
}

describe("behavior reports from the built CLI", () => {
  it.each(["directory", "independent archive", "test-built archive"])(
    "retains facts from a %s with no findings",
    async (representation) => {
      const archive = join(root, "fixture.vsix");
      await writeFile(
        archive,
        createTestZip([
          {
            name: "extension/package.json",
            content: await readFile(join(FIXTURE, "package.json"), "utf8"),
          },
          { name: "extension/main.js", content: source },
        ]),
      );
      const target =
        representation === "directory"
          ? directory
          : representation === "independent archive"
            ? join(FIXTURE, "fixture.vsix")
            : archive;
      const result = await runCli(["scan", target, ...CONTROLS, "--output", "json"]);
      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      const report = JSON.parse(result.stdout) as ScanResult;
      expect(report.findings).toEqual([]);
      expect(report.metadata.coverage).toEqual({
        degraded: false,
        warnings: [],
        incompleteModules: [],
      });
      assertObservations(report.observations);
    },
  );

  it("keeps the independently produced archive pinned", async () => {
    const bytes = await readFile(join(FIXTURE, "fixture.vsix"));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "eb000cca1b3780b94d1847d7618be3eb82049053895ac6b9857e197e70be92a4",
    );
  });

  it("shows ordinary source behavior in info and text scan output", async () => {
    const info = await runCli(["info", directory, "--verbose"]);
    const text = await runCli(["scan", directory, ...CONTROLS]);
    expect(info.status).toBe(0);
    expect(text.status).toBe(0);
    for (const api of [
      "global.fetch",
      "fs.readFileSync",
      "fs.writeFileSync",
      "child_process.spawn",
      "global.eval",
    ]) {
      expect(info.stdout).toContain(api);
      expect(text.stdout).toContain(api);
    }
    expect(info.stdout).toContain("main.js:5");
    expect(text.stdout).toContain("No findings at the selected severity.");
  });

  it("retains facts in SARIF without creating security alerts for them", async () => {
    const result = await runCli(["scan", directory, ...CONTROLS, "--output", "sarif"]);
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout) as ReturnType<typeof toSarif>;
    expect(report.runs[0]?.results).toEqual([]);
    assertObservations(report.runs[0]?.properties?.observations ?? []);
  });

  it("labels heuristic references separately from observed credential access", async () => {
    await writeFile(
      join(directory, "main.js"),
      'const docs = {browser: "Firefox", storage: "IndexedDB", api: "readFileSync"};',
    );
    const result = await runCli(["info", directory, "--verbose"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/Credentials\s+✗ No source observations/);
    expect(result.stdout).toContain(
      "Indicators: YARA rule match: STEALER_JS_Browser_Data_Theft_Jan25",
    );
  });

  it("preserves observations and source attribution for an installed extension", async () => {
    const result = await runCli([
      "scan-installed",
      "--extensions-dir",
      join(root, "store"),
      ...CONTROLS,
      "--output",
      "json",
    ]);
    expect(result.status).toBe(0);
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(batch.errors).toEqual([]);
    expect(batch.results).toHaveLength(1);
    expect(batch.results[0]?.metadata.sourcePath).toBe(await realpath(directory));
    assertObservations(batch.results[0]?.observations ?? []);
  });

  it.each(["json", "sarif"])(
    "preserves partial observations and coverage failure in %s",
    async (output) => {
      await writeFile(join(directory, "main.js"), `${source}\nconst broken;`);
      const result = await runCli(["scan", directory, ...CONTROLS, "--strict", "--output", output]);
      expect(result.status).toBe(2);
      const json = JSON.parse(result.stdout) as ScanResult;
      const sarif = JSON.parse(result.stdout) as ReturnType<typeof toSarif>;
      const coverage =
        output === "json" ? json.metadata.coverage : sarif.runs[0]?.properties?.coverage;
      const observations =
        output === "json" ? json.observations : sarif.runs[0]?.properties?.observations;
      const findings = output === "json" ? json.findings : sarif.runs[0]?.results;
      const completed =
        output === "json"
          ? !json.metadata.coverage.degraded
          : sarif.runs[0]?.invocations?.[0]?.executionSuccessful;
      expect(coverage?.incompleteModules).toEqual(["ast"]);
      expect(coverage?.degraded).toBe(true);
      expect(findings).toEqual([]);
      expect(completed).toBe(false);
      assertObservations(observations ?? []);
    },
  );
});
