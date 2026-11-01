import { spawnSync } from "node:child_process";
import { mkdir, mkdtempDisposable, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";

const cli = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function fixture(root: string): Promise<{ target: string; hook: string }> {
  const target = join(root, "extension");
  const hook = join(root, "network.mjs");
  await mkdir(target);
  await writeFile(
    join(target, "package.json"),
    JSON.stringify({
      name: "fixture",
      publisher: "test",
      version: "1.0.0",
      repository: "example/source",
    }),
  );
  await writeFile(
    hook,
    `
    globalThis.fetch = async (input) => {
      if (new URL(input).origin !== "https://api.github.com") throw new Error("Unexpected origin");
      if (process.env.REPOSITORY_TEST_RESULT === "error") return new Response(null, {status: 503});
      const commits = process.env.REPOSITORY_TEST_RESULT === "empty" ? [] : [{sha: "a".repeat(40)}];
      return Response.json(commits);
    };
  `,
  );
  return { target, hook };
}

function run(
  input: { target: string; hook: string },
  format: string,
  result: string,
): { status: number | null; output: unknown; stderr: string } {
  const child = spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(input.hook).href,
      cli,
      "scan",
      input.target,
      "--module",
      "repository",
      "--check-repository",
      "--output",
      format,
      "--strict",
    ],
    {
      encoding: "utf8",
      timeout: 20_000,
      env: { ...process.env, GITHUB_TOKEN: "", REPOSITORY_TEST_RESULT: result, NO_COLOR: "1" },
    },
  );
  if (child.error !== undefined) throw child.error;
  if (child.stdout.trim() === "") {
    throw new Error(`CLI produced no JSON (exit ${String(child.status)}): ${child.stderr}`);
  }
  const output: unknown = JSON.parse(child.stdout);
  return { status: child.status, output, stderr: child.stderr };
}

describe("repository CLI results", () => {
  it("reports a populated repository as covered in JSON", async () => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-cli-"));
    const result = run(await fixture(root.path), "json", "healthy");
    expect(result.status).toBe(0);
    expect(result.output).toMatchObject({
      findings: [],
      metadata: { coverage: { degraded: false } },
      inventory: [{ name: "Repository", enabled: true }],
    });
  });

  it("renders empty repositories as low-severity SARIF findings", async () => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-cli-"));
    const result = run(await fixture(root.path), "sarif", "empty");
    expect(result.status).toBe(1);
    expect(result.output).toMatchObject({
      runs: [{ results: [{ ruleId: "REPOSITORY_EMPTY", level: "note" }] }],
    });
  });

  it("fails strict mode when repository coverage is unavailable", async () => {
    await using root = await mkdtempDisposable(join(tmpdir(), "vsix-repository-cli-"));
    const result = run(await fixture(root.path), "json", "error");
    expect(result.status).toBe(2);
    expect(result.output).toMatchObject({
      findings: [],
      metadata: { coverage: { degraded: true, incompleteModules: ["repository"] } },
    });
  });
});
