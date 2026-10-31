import { spawn } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { BatchScanResult } from "#internal/scanner/types.js";
import type { toSarifCombined } from "#internal/formatters.js";

const CLI_PATH = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const COMMON = ["--output", "json", "--module", "manifest", "--no-network"];
let home = "";

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "vsix-installed-cli-"));
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], overrides: NodeJS.ProcessEnv = {}): Promise<CliResult> {
  return new Promise((resolvePromise, reject) => {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NO_COLOR: "1",
      ...overrides,
    };
    delete env["FORCE_COLOR"];
    delete env["VSIX_AUDIT_ZOO_PATH"];
    delete env["VSIX_AUDIT_CACHE_DIR"];
    const child = spawn(process.execPath, [CLI_PATH, "scan-installed", ...args], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => resolvePromise({ status, stdout, stderr }));
  });
}

async function extension(
  store: string,
  name = "clean",
  source = "throw new Error('never run');",
): Promise<string> {
  const path = join(store, `test.${name}-1.0.0`);
  await mkdir(path, { recursive: true });
  await writeFile(
    join(path, "package.json"),
    JSON.stringify({
      name,
      publisher: "test",
      version: "1.0.0",
      main: "main.js",
    }),
  );
  await writeFile(join(path, "main.js"), source);
  return realpath(path);
}

describe("installed scan command", () => {
  it("documents editor selection, custom paths, and shared scan controls", async () => {
    const result = await runCli(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--editor");
    expect(result.stdout).toContain("--extensions-dir");
    expect(result.stdout).toContain("--strict");
    expect(result.stdout).not.toContain("--all-registries");
  });

  it("scans all detected editor stores without executing extension code", async () => {
    const paths = [];
    for (const directory of [".vscode", ".vscode-insiders", ".cursor"]) {
      paths.push(await extension(join(home, directory, "extensions")));
    }
    const result = await runCli(COMMON);
    const batch = JSON.parse(result.stdout) as BatchScanResult;

    expect(result.status).toBe(0);
    expect(batch.summary.scannedFiles).toBe(3);
    expect(batch.results.map((scan) => scan.metadata.sourcePath).toSorted()).toEqual(
      paths.toSorted(),
    );
    expect(result.stderr).toContain("Scanning 3 installed extension(s).");
    expect(result.stdout.trimStart().startsWith("{")).toBe(true);
  });

  it("restricts scanning to the chosen editor", async () => {
    await extension(join(home, ".vscode", "extensions"), "suspicious", "eval(code);");
    const cursor = await extension(join(home, ".cursor", "extensions"));
    const result = await runCli(["--editor", "cursor", "--module", "ast", "--output", "json"]);
    const batch = JSON.parse(result.stdout) as BatchScanResult;

    expect(result.status).toBe(0);
    expect(batch.results.map((scan) => scan.metadata.sourcePath)).toEqual([cursor]);
  });

  it("accepts a custom directory containing spaces", async () => {
    const store = join(home, "custom extensions");
    const installed = await extension(store);
    const result = await runCli(["--extensions-dir", store, ...COMMON]);
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(result.status).toBe(0);
    expect(batch.results[0]?.metadata.sourcePath).toBe(installed);
  });
});

describe("installed finding reports", () => {
  it("shows requested timing data for a clean extension", async () => {
    await extension(join(home, ".vscode", "extensions"));
    const result = await runCli(["--module", "ast", "--profile"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Module timings:");
  });

  it("keeps large JSON reports complete when stdout is a pipe", async () => {
    const store = join(home, ".vscode", "extensions");
    for (let index = 0; index < 120; index++) {
      await extension(store, `extension-${index}`, "eval(code);");
    }
    const result = await runCli(["--module", "ast", "--output", "json"]);
    expect(result.status).toBe(1);
    expect(result.stdout.length).toBeGreaterThan(65_536);
    expect((JSON.parse(result.stdout) as BatchScanResult).results).toHaveLength(120);
  });

  it("returns findings and preserves the intelligence selection", async () => {
    await extension(join(home, ".vscode", "extensions"), "suspicious", "eval(code);");
    const result = await runCli(["--module", "ast", "--output", "json", "--no-threat-intel"]);
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(result.status).toBe(1);
    expect(batch.results[0]?.findings.map((finding) => finding.id)).toContain("AST_EVAL_DYNAMIC");
    expect(batch.results[0]?.metadata.intel).toBe("none");
  });

  it("distinguishes matching extension names in separate editor stores in SARIF", async () => {
    const paths = [];
    for (const directory of [".vscode", ".cursor"]) {
      paths.push(await extension(join(home, directory, "extensions"), "same", "eval(code);"));
    }
    const result = await runCli(["--module", "ast", "--output", "sarif"]);
    const sarif = JSON.parse(result.stdout) as ReturnType<typeof toSarifCombined>;
    const uris = sarif.runs.map(
      (run) => run.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri,
    );

    expect(result.status).toBe(1);
    expect(uris.toSorted()).toEqual(
      paths.map((path) => pathToFileURL(join(path, "main.js")).href).toSorted(),
    );
  });

  it("prints the installed path alongside text findings", async () => {
    const path = await extension(join(home, ".cursor", "extensions"), "same", "eval(code);");
    const result = await runCli(["--module", "ast"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain(path);
    expect(result.stdout).toContain("eval()");
  });
});

describe("installed scan failures", () => {
  it("explains strict coverage failures with high severity filters", async () => {
    await extension(join(home, ".vscode", "extensions"));
    const result = await runCli(["--module", "yara", "--strict", "--severity", "critical"], {
      PATH: "",
    });
    expect(result.status).toBe(2);
    expect(result.stdout).toContain("Coverage degraded");
    expect(result.stdout).not.toContain("No issues found across all extensions");
  });

  it("returns exit code 2 for a partial scan failure", async () => {
    const store = join(home, ".vscode", "extensions");
    await extension(store);
    const broken = join(store, "test.broken-1.0.0");
    await mkdir(broken);
    const result = await runCli(COMMON);
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(result.status).toBe(2);
    expect(batch.summary).toMatchObject({ scannedFiles: 1, failedFiles: 1 });
    expect(batch.errors[0]?.path).toBe(await realpath(broken));
  });

  it("gives errors priority over findings in the exit code", async () => {
    const store = join(home, ".vscode", "extensions");
    await extension(store, "suspicious", "eval(code);");
    await mkdir(join(store, "test.broken-1.0.0"));
    const result = await runCli(["--module", "ast", "--output", "json"]);
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(result.status).toBe(2);
    expect(batch.summary.totalFindings).toBeGreaterThan(0);
    expect(batch.errors).toHaveLength(1);
  });

  it("reports failed extension paths when all scans fail in SARIF", async () => {
    const broken = join(home, ".vscode", "extensions", "test.broken-1.0.0");
    await mkdir(broken, { recursive: true });
    const result = await runCli(["--module", "manifest", "--output", "sarif"]);
    const sarif = JSON.parse(result.stdout) as ReturnType<typeof toSarifCombined>;
    expect(result.status).toBe(2);
    expect(sarif.runs[0]?.invocations?.[0]?.executionSuccessful).toBe(false);
    expect(sarif.runs[0]?.invocations?.[0]?.toolExecutionNotifications[0]?.message.text).toContain(
      "test.broken-1.0.0",
    );
  });

  it.each(["--strict", "--require-yara"])("honors %s when YARA is unavailable", async (flag) => {
    await extension(join(home, ".vscode", "extensions"));
    const result = await runCli(["--module", "yara", "--output", "json", flag], { PATH: "" });
    const batch = JSON.parse(result.stdout) as BatchScanResult;
    expect(result.status).toBe(2);
    expect(batch.results[0]?.metadata.coverage?.unavailableModules).toContain("yara");
  });
});

describe("installed scan argument validation", () => {
  it("rejects an unexpected positional target", async () => {
    const result = await runCli(["some.publisher"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("too many arguments");
  });

  it("reports no installed extensions with an actionable error", async () => {
    const result = await runCli(COMMON);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("No installed extensions found");
    expect(result.stderr).toContain("--extensions-dir");
  });

  it.each(["0", "-1", "1.5", "2junk", "9007199254740992"])(
    "rejects invalid --jobs %s",
    async (jobs) => {
      const result = await runCli(["--jobs", jobs]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("positive safe integer");
    },
  );

  it("rejects an unknown editor", async () => {
    const result = await runCli(["--editor", "unknown"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Allowed choices");
  });

  it("rejects an editor combined with a custom directory", async () => {
    const result = await runCli(["--editor", "vscode", "--extensions-dir", home]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("cannot be used with");
  });

  it.each([
    ["--module", "unknown", "Unknown module"],
    ["--output", "xml", "Invalid output format"],
    ["--severity", "urgent", "Invalid severity"],
    ["--threat-intel", "remote", "Invalid intel mode"],
  ])("validates the shared %s control", async (flag, value, message) => {
    const result = await runCli([flag, value]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(message);
  });
});
