import { createHash } from "node:crypto";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CleanCorpusEntry } from "#internal/scanner/clean-corpus.js";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const scripts = ["download-clean-corpus.mjs", "report-clean-corpus.mjs"];
let root = "";
let manifestPath = "";

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-corpus-scripts-"));
  manifestPath = join(root, "manifest.json");
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

function run(script: string, args: string[]): SpawnSyncReturns<string> {
  const result = spawnSync(process.execPath, [join(repoRoot, "scripts", script), ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 10_000,
  });
  if (result.error !== undefined) throw result.error;
  return result;
}

async function manifest(extensions: CleanCorpusEntry[] = []): Promise<void> {
  await writeFile(
    manifestPath,
    JSON.stringify({ version: 1, description: "Script regression fixture", extensions }),
  );
}

const artifact = Buffer.from("invalid ZIP fixture");
const entry: CleanCorpusEntry = {
  id: "test.extension",
  publisher: "test",
  name: "extension",
  version: "1.0.0",
  registry: "marketplace",
  category: "baseline",
  sha256: createHash("sha256").update(artifact).digest("hex"),
};

function reportArgs(): string[] {
  return ["--manifest", manifestPath, "--input", root, "--json"];
}

describe.each(scripts)("%s", (script) => {
  it.each(["--manifest", "--unknown"])("rejects invalid argument %s", (argument) => {
    const result = run(script, [argument]);
    expect(result.status).toBeGreaterThan(0);
    expect(result.stderr).toContain(argument);
    expect(result.stdout).toBe("");
  });

  it("rejects malformed JSON", async () => {
    await writeFile(manifestPath, "{");
    const result = run(script, ["--manifest", manifestPath]);
    expect(result.status).toBeGreaterThan(0);
    expect(result.stderr).toMatch(/JSON|property name/i);
  });

  it("rejects an invalid manifest through the shared validator", async () => {
    await writeFile(manifestPath, JSON.stringify({ version: 1, extensions: [] }));
    const result = run(script, ["--manifest", manifestPath]);
    expect(result.status).toBeGreaterThan(0);
    expect(result.stderr).toContain("description");
  });
});

describe("clean corpus report", () => {
  it("reports an empty corpus without findings or errors", async () => {
    await manifest();
    const result = run("report-clean-corpus.mjs", reportArgs());
    const report: unknown = JSON.parse(result.stdout);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(report).toMatchObject({
      summary: { total: 0, scanned: 0, errors: 0, neverFindings: 0, findings: { total: 0 } },
      extensions: [],
    });
  });

  it.each(["missing", "hash mismatch", "invalid ZIP"])(
    "reports %s artifacts and exits with a scanner error",
    async (failure) => {
      await manifest([entry]);
      const path = join(root, "test.extension-1.0.0.vsix");
      if (failure !== "missing") {
        await writeFile(path, failure === "hash mismatch" ? "wrong hash" : artifact);
      }
      const result = run("report-clean-corpus.mjs", reportArgs());
      const report: unknown = JSON.parse(result.stdout);
      expect(result.status).toBe(2);
      expect(report).toMatchObject({
        summary: { total: 1, scanned: 0, errors: 1 },
        extensions: [{ id: entry.id, findings: { total: 0 }, neverFindings: [] }],
      });
      expect(result.stdout).toContain('"error":');
      expect(result.stderr).toBe("");
    },
  );
});

describe("clean corpus download", () => {
  it("reuses a file with the pinned hash without contacting a registry", async () => {
    await manifest([entry]);
    await writeFile(join(root, "test.extension-1.0.0.vsix"), artifact);
    const result = run("download-clean-corpus.mjs", ["--manifest", manifestPath, "--output", root]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`ok test.extension-1.0.0.vsix ${entry.sha256}`);
    expect(result.stderr).toBe("");
  });
});

describe("findings collector", () => {
  it("builds a fresh checkout and reports registry failures without fetching packages", async () => {
    const npmCli = process.env["npm_execpath"];
    if (npmCli === undefined) throw new Error("Run smoke tests with npm run test:cli");
    await cp(join(repoRoot, "src"), join(root, "src"), { recursive: true });
    await cp(join(repoRoot, "tsconfig.json"), join(root, "tsconfig.json"));
    await cp(join(repoRoot, "package.json"), join(root, "package.json"));
    await mkdir(join(root, "scripts"));
    await cp(
      join(repoRoot, "scripts", "collect-findings.ts"),
      join(root, "scripts", "collect-findings.ts"),
    );
    await symlink(join(repoRoot, "node_modules"), join(root, "node_modules"), "junction");
    const preload = join(root, "offline.mjs");
    await writeFile(
      preload,
      [
        "globalThis.fetch = async () => new Response(null, {",
        '  status: 503, statusText: "Offline fixture",',
        "});",
      ].join("\n"),
    );

    const result = spawnSync(process.execPath, [npmCli, "run", "--silent", "findings:collect"], {
      cwd: root,
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, NODE_OPTIONS: `--import=${pathToFileURL(preload).href}` },
    });
    if (result.error !== undefined) throw result.error;
    const report = JSON.parse(result.stdout) as { summary: { total: number; failed: number } };
    expect(result.status).toBe(1);
    expect(report.summary.total).toBeGreaterThan(0);
    expect(report.summary.failed).toBe(report.summary.total);
    expect(result.stdout).toContain("Offline fixture");
    expect(result.stderr).toBe("");
    expect((await stat(join(root, "dist", "scanner", "index.js"))).isFile()).toBe(true);
  }, 40_000);
});
