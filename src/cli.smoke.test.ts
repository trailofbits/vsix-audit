import type { BatchScanResult, ScanResult } from "#internal/scanner/types.js";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createTestZip } from "#internal/test-support/zip.js";
import { runCli } from "#internal/test-support/cli.js";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

describe("retired CLI options", () => {
  it.each([["--no-network"], ["--module=package"]])(
    "rejects %j with a usage error",
    async (option) => {
      const result = await runCli(["scan", "fixture.vsix", option]);
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/unknown (?:option|module)/i);
    },
  );
});

describe("terminal output safety", () => {
  let root = "";
  const attack = "unsafe\x1b[2J\x1b[H\x1b[8m\r\x9b2J\u202e";
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "vsix-terminal-cli-"));
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({
        name: "fixture",
        displayName: attack,
        description: attack,
        publisher: "test",
        version: "1.0.0",
        main: "main.js",
        activationEvents: [attack],
      }),
    );
    await writeFile(join(root, "main.js"), "throw new Error('never execute'); eval(code);");
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("escapes metadata while preserving the CLI's own colors", async () => {
    const result = await runCli(["scan", root, "--module", "ast"], {
      env: { FORCE_COLOR: "1", NO_COLOR: undefined },
    });
    expect(result.status).toBe(1);
    expect(result.stdout).not.toContain("\x1b[2J");
    expect(result.stdout).not.toContain("\x1b[8m");
    expect(result.stdout).not.toContain("\r");
    expect(result.stdout).not.toContain("\x9b");
    expect(result.stdout).toContain("\\x1b[2J");
    expect(result.stdout).toContain("\x1b[1m");
  });

  it("escapes metadata and capability evidence in info output", async () => {
    const result = await runCli(["info", root, "--verbose"], { env: { PATH: "" } });
    expect(result.status).toBe(0);
    expect(result.stdout).not.toContain("\x1b");
    expect(result.stdout).not.toContain("\r");
    expect(result.stdout).not.toContain("\x9b");
    expect(result.stdout).toContain("\\x1b[2J");
  });

  it("escapes local scan errors on stderr", async () => {
    const result = await runCli(["scan", join(root, attack), "--output", "json"]);
    expect(result.status).toBe(2);
    expect(result.stderr).not.toContain("\x1b");
    expect(result.stderr).not.toContain("\r");
    expect(result.stderr).toContain("\\x1b[2J");
  });

  it("escapes Commander argument errors", async () => {
    const result = await runCli(["scan-installed", "--editor", attack]);
    expect(result.status).toBe(2);
    expect(result.stderr).not.toContain("\x1b");
    expect(result.stderr).not.toContain("\r");
    expect(result.stderr).toContain("\\x1b[2J");
  });

  it("escapes custom cache paths", async () => {
    const result = await runCli(["cache", "path"], {
      env: { VSIX_AUDIT_CACHE_DIR: join(root, attack) },
    });
    expect(result.status).toBe(0);
    expect(result.stdout).not.toContain("\x1b");
    expect(result.stdout).toContain("\\x1b[2J");
  });
});

describe("CLI cache options", () => {
  let testDir: string;
  let cacheDir: string;
  let scanTempDir: string;
  let downloadDir: string;
  let payloadPath: string;
  let env: NodeJS.ProcessEnv;
  const filename = "test.extension-1.0.0.vsix";
  const registries = ["marketplace", "openvsx", "cursor"];

  beforeEach(async () => {
    testDir = await mkdtemp(join(tmpdir(), "vsix-audit-cli-cache-"));
    cacheDir = join(testDir, "cache");
    scanTempDir = join(testDir, "scan-temp");
    downloadDir = join(testDir, "downloads");
    payloadPath = join(testDir, "payload.vsix");
    await mkdir(scanTempDir);
    await mkdir(downloadDir);
    for (const registry of registries) {
      await mkdir(join(cacheDir, registry), { recursive: true });
      await writeFile(join(cacheDir, registry, filename), "existing cached VSIX");
    }
    await writeFile(
      payloadPath,
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({ name: "extension", publisher: "test", version: "1.0.0" }),
        },
      ]),
    );

    const mockPath = join(testDir, "registry.mjs");
    await writeFile(
      mockPath,
      `import { readFileSync } from "node:fs";
globalThis.fetch = async (input) => {
  const url = new URL(input);
  if (url.hostname === "open-vsx.org") {
    const failure = process.env["VSIX_AUDIT_TEST_REGISTRY_FAILURE"];
    if (failure === "outage") throw new Error("Simulated registry outage");
    if (failure === "missing") return new Response("Not found", { status: 404 });
    if (failure === "scan" && url.pathname.endsWith(".vsix")) return new Response("Invalid VSIX");
  }
  if (url.pathname.endsWith("/extensionquery")) {
    return Response.json({ results: [{ extensions: [{
      publisher: { publisherName: "test" }, extensionName: "extension",
      versions: [{ version: "1.0.0", lastUpdated: "2026-10-30T00:00:00Z", files: [] }]
    }] }] });
  }
  if (url.href === "https://open-vsx.org/api/test/extension") {
    return Response.json({ namespace: "test", name: "extension", version: "1.0.0" });
  }
  if (!url.pathname.endsWith(".vsix") && !url.pathname.endsWith("/VSIXPackage") &&
      !url.pathname.endsWith("/Microsoft.VisualStudio.Services.VSIXPackage") &&
      !url.pathname.endsWith("/vspackage")) {
    throw new Error("Unexpected request: " + url);
  }
  if (process.env["VSIX_AUDIT_TEST_DOWNLOAD_FAILURE"]) {
    return new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        setTimeout(() => controller.error(new Error("Download interrupted")), 20);
      }
    }));
  }
  return new Response(readFileSync(process.env["VSIX_AUDIT_TEST_PAYLOAD"]));
};
`,
    );
    env = {
      NODE_OPTIONS: `--import=${pathToFileURL(mockPath).href}`,
      VSIX_AUDIT_CACHE_DIR: cacheDir,
      VSIX_AUDIT_TEST_PAYLOAD: payloadPath,
      TMPDIR: scanTempDir,
      TMP: scanTempDir,
      TEMP: scanTempDir,
    };
  });

  afterEach(async () => {
    await rm(testDir, { recursive: true, force: true });
  });

  async function expectCacheUnchanged(): Promise<void> {
    expect(await readdir(cacheDir)).toEqual([...registries].sort());
    for (const registry of registries) {
      expect(await readdir(join(cacheDir, registry))).toEqual([filename]);
      expect(await readFile(join(cacheDir, registry, filename), "utf8")).toBe(
        "existing cached VSIX",
      );
    }
  }

  it("scans a fresh download and removes temporary files", async () => {
    const result = await runCli(
      ["scan", "openvsx:test.extension", "--no-cache", "--output", "json", "--module", "manifest"],
      { env },
    );

    expect(result.status).toBe(0);
    expect((JSON.parse(result.stdout) as ScanResult).findings).toEqual([]);
    expect(result.stderr).not.toContain("Using cached");
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
  });

  it("cleans up a temporary download when scanning fails", async () => {
    await writeFile(payloadPath, "invalid VSIX");

    const result = await runCli(["scan", "openvsx:test.extension", "--no-cache"], { env });

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Error:");
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
  });

  it("removes temporary files when a scan reports findings", async () => {
    await writeFile(
      payloadPath,
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({
            name: "extension",
            publisher: "test",
            version: "1.0.0",
            activationEvents: ["*"],
          }),
        },
      ]),
    );

    const result = await runCli(
      ["scan", "openvsx:test.extension", "--no-cache", "--output", "json", "--module", "manifest"],
      { env },
    );

    expect(result.status).toBe(1);
    expect((JSON.parse(result.stdout) as ScanResult).findings).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "ACTIVATION_WILDCARD" })]),
    );
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
  });

  it("cleans up a partial download when the network stream fails", async () => {
    const result = await runCli(["scan", "openvsx:test.extension", "--no-cache"], {
      env: { ...env, VSIX_AUDIT_TEST_DOWNLOAD_FAILURE: "1" },
    });

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Download interrupted");
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
  });

  it("bypasses the cache and cleans up downloads from all registries", async () => {
    const result = await runCli(
      [
        "scan",
        "test.extension",
        "--all-registries",
        "--no-cache",
        "--output",
        "json",
        "--module",
        "manifest",
      ],
      { env },
    );

    expect(result.status).toBe(0);
    expect(
      (JSON.parse(result.stdout) as BatchScanResult).results.map((scan) => scan.metadata.registry),
    ).toEqual(registries);
    expect(result.stderr).toContain("Downloading from marketplace:");
    expect(result.stderr).toContain("Downloading from openvsx:");
    expect(result.stderr).toContain("Downloading from cursor:");
    expect(result.stderr).not.toContain("Using cached");
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
  });

  it.each(["outage", "missing", "scan"])(
    "retains partial registry failure %s in JSON and returns an error",
    async (failure) => {
      const result = await runCli(
        [
          "scan",
          "test.extension",
          "--all-registries",
          "--no-cache",
          "--output",
          "json",
          "--module",
          "manifest",
        ],
        { env: { ...env, VSIX_AUDIT_TEST_REGISTRY_FAILURE: failure } },
      );
      const batch = JSON.parse(result.stdout) as BatchScanResult;
      expect(result.status).toBe(2);
      expect(batch.summary).toMatchObject({ totalFiles: 3, scannedFiles: 2, failedFiles: 1 });
      expect(batch.errors[0]?.path).toBe("openvsx:test/extension");
      expect(result.stderr).toContain(
        failure === "missing" ? "Not found in openvsx" : "Failed in openvsx",
      );
      expect(await readdir(scanTempDir)).toEqual([]);
      await expectCacheUnchanged();
    },
  );

  it("retains registry failures as SARIF execution notifications", async () => {
    const result = await runCli(
      [
        "scan",
        "test.extension",
        "--all-registries",
        "--no-cache",
        "--output",
        "sarif",
        "--module",
        "manifest",
      ],
      { env: { ...env, VSIX_AUDIT_TEST_REGISTRY_FAILURE: "outage" } },
    );
    const report = JSON.parse(result.stdout) as { runs: Array<{ invocations?: unknown }> };
    expect(result.status).toBe(2);
    expect(report.runs).toContainEqual(
      expect.objectContaining({
        invocations: [
          expect.objectContaining({
            executionSuccessful: false,
            toolExecutionNotifications: [expect.objectContaining({ level: "error" })],
          }),
        ],
      }),
    );
  });

  it.each([false, true])(
    "keeps an uncached download with explicit output=%s",
    async (explicitOutput) => {
      await writeFile(join(downloadDir, filename), "existing local VSIX");
      const args = ["download", "openvsx:test.extension", "--no-cache"];
      if (explicitOutput) args.push("--output", downloadDir);

      const result = await runCli(args, { cwd: explicitOutput ? testDir : downloadDir, env });

      expect(result.status).toBe(0);
      expect(result.stdout).not.toContain("Using cached");
      expect(await readFile(join(downloadDir, filename))).toEqual(await readFile(payloadPath));
      expect(await readdir(downloadDir)).toEqual([filename]);
      expect(await readdir(scanTempDir)).toEqual([]);
      await expectCacheUnchanged();
    },
  );

  it.each([false, true])(
    "preserves an existing VSIX after a failed uncached download with explicit output=%s",
    async (explicitOutput) => {
      const destination = join(downloadDir, filename);
      const original = await readFile(payloadPath);
      await writeFile(destination, original);
      const args = ["download", "openvsx:test.extension", "--no-cache"];
      if (explicitOutput) args.push("--output", downloadDir);

      const result = await runCli(args, {
        cwd: explicitOutput ? testDir : downloadDir,
        env: { ...env, VSIX_AUDIT_TEST_DOWNLOAD_FAILURE: "1" },
      });

      expect(result.status).toBe(2);
      expect(result.stderr).toContain("Download interrupted");
      expect(await readFile(destination)).toEqual(original);
      expect(await readdir(downloadDir)).toEqual([filename]);
      expect(await readdir(scanTempDir)).toEqual([]);
      await expectCacheUnchanged();
    },
  );

  it("keeps --force downloads in the persistent cache", async () => {
    const result = await runCli(["download", "openvsx:test.extension", "--force"], { env });

    expect(result.status).toBe(0);
    expect(await readFile(join(cacheDir, "openvsx", filename))).toEqual(
      await readFile(payloadPath),
    );
    expect(await readdir(scanTempDir)).toEqual([]);
    expect(await readdir(downloadDir)).toEqual([]);
  });
});

describe("built CLI smoke tests", () => {
  let tempRoot = "";
  let cleanExtension = "";
  let suspiciousExtension = "";
  let batchDir = "";
  let degradedVsix = "";

  beforeAll(async () => {
    tempRoot = await mkdtemp(join(tmpdir(), "vsix-audit-cli-"));
    cleanExtension = join(tempRoot, "clean");
    suspiciousExtension = join(tempRoot, "suspicious");
    batchDir = join(tempRoot, "batch");
    degradedVsix = join(tempRoot, "missing-main.vsix");

    await mkdir(cleanExtension, { recursive: true });
    await writeFile(
      join(cleanExtension, "package.json"),
      JSON.stringify({
        name: "clean",
        publisher: "test",
        version: "1.0.0",
      }),
    );

    await mkdir(suspiciousExtension, { recursive: true });
    await writeFile(
      join(suspiciousExtension, "package.json"),
      JSON.stringify({
        name: "suspicious",
        publisher: "test",
        version: "1.0.0",
        main: "main.js",
        dependencies: {
          "vscode-darcula": "1.0.0",
        },
      }),
    );
    await writeFile(
      join(suspiciousExtension, "main.js"),
      'const cmd = "npx github:nrwl/nx#0123456789abcdef0123456789abcdef01234567";',
    );

    await writeFile(
      degradedVsix,
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({
            name: "missing-main",
            publisher: "test",
            version: "1.0.0",
            main: "main.js",
          }),
        },
      ]),
    );

    await mkdir(batchDir, { recursive: true });
    await writeFile(
      join(batchDir, "clean.vsix"),
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({
            name: "clean-batch",
            publisher: "test",
            version: "1.0.0",
          }),
        },
      ]),
    );
    await writeFile(
      join(batchDir, "suspicious.vsix"),
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({
            name: "suspicious-batch",
            publisher: "test",
            version: "1.0.0",
            main: "main.js",
          }),
        },
        {
          name: "extension/main.js",
          content: 'const cmd = "npx github:nrwl/nx#0123456789abcdef0123456789abcdef01234567";',
        },
      ]),
    );
  });

  afterAll(async () => {
    await rm(tempRoot, { recursive: true, force: true });
  });

  it("returns exit code 0 and JSON for a clean extension", async () => {
    const result = await runCli([
      "scan",
      cleanExtension,
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
    ]);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[] };

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(parsed.findings).toHaveLength(0);
  });

  it("returns exit code 1 and JSON findings for a suspicious extension", async () => {
    const result = await runCli([
      "scan",
      suspiciousExtension,
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
    ]);
    const parsed = JSON.parse(result.stdout) as { findings: Array<{ id: string }> };

    expect(result.status).toBe(1);
    expect(parsed.findings.map((finding) => finding.id)).toContain("GITHUB_SHA_EXECUTION");
  });

  it("emits SARIF for findings", async () => {
    const result = await runCli([
      "scan",
      suspiciousExtension,
      "--output",
      "sarif",
      "--module",
      "manifest,execution,deps,intel",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      version: string;
      runs: Array<{ results: Array<{ ruleId: string }> }>;
    };

    expect(result.status).toBe(1);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0]?.results.map((finding) => finding.ruleId)).toContain(
      "GITHUB_SHA_EXECUTION",
    );
  });

  it("honors module filtering", async () => {
    const result = await runCli([
      "scan",
      suspiciousExtension,
      "--output",
      "json",
      "--module",
      "ast",
    ]);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[] };

    expect(result.status).toBe(0);
    expect(parsed.findings).toHaveLength(0);
  });

  it("keeps non-recursive warning text off JSON stdout", async () => {
    const result = await runCli([
      "scan",
      cleanExtension,
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
      "--jobs",
      "2",
    ]);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[] };

    expect(result.status).toBe(0);
    expect(result.stdout.trimStart().startsWith("{")).toBe(true);
    expect(result.stderr).toContain("--jobs is only used with --recursive");
    expect(parsed.findings).toHaveLength(0);
  });

  it("honors --no-threat-intel without disabling generic detections", async () => {
    const result = await runCli([
      "scan",
      suspiciousExtension,
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
      "--no-threat-intel",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      metadata: { intel?: string };
      findings: Array<{ id: string }>;
    };
    const ids = parsed.findings.map((finding) => finding.id);

    expect(result.status).toBe(1);
    expect(parsed.metadata.intel).toBe("none");
    expect(ids).toContain("GITHUB_SHA_EXECUTION");
    expect(ids).not.toContain("MALICIOUS_NPM_PACKAGE");
  });

  it.each(["low", "critical"])(
    "returns strict exit code 2 for recovered parsing at %s severity",
    async (severity) => {
      const directory = join(tempRoot, `recoverable-${severity}`);
      await mkdir(directory);
      await writeFile(
        join(directory, "package.json"),
        JSON.stringify({ name: "recovery", publisher: "test", version: "1.0.0", main: "main.js" }),
      );
      await writeFile(join(directory, "main.js"), "const missing;");
      const result = await runCli([
        "scan",
        directory,
        "--output=json",
        "--module=ast",
        `--severity=${severity}`,
        "--strict",
      ]);
      const parsed = JSON.parse(result.stdout) as ScanResult;
      expect(result.status).toBe(2);
      expect(parsed.metadata.coverage.degraded).toBe(true);
      expect(parsed.metadata.coverage.warnings).toEqual([expect.stringContaining('"main.js"')]);
    },
  );

  it("returns exit code 2 for strict coverage degradation", async () => {
    const result = await runCli([
      "scan",
      degradedVsix,
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
      "--strict",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      findings: Array<{ id: string }>;
      metadata: { coverage: { degraded: boolean } };
    };

    expect(result.status).toBe(2);
    expect(parsed.metadata.coverage.degraded).toBe(true);
    expect(parsed.findings.map((finding) => finding.id)).toContain(
      "ARCHIVE_REFERENCED_FILE_MISSING",
    );
  });

  it("returns exit code 2 when --require-yara excludes the yara module", async () => {
    const result = await runCli([
      "scan",
      cleanExtension,
      "--module",
      "manifest,execution,deps,intel",
      "--require-yara",
    ]);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "--require-yara cannot be used when the module filter excludes yara",
    );
  });

  it("emits parseable recursive JSON on stdout", async () => {
    const result = await runCli([
      "scan",
      batchDir,
      "--recursive",
      "--jobs",
      "2",
      "--output",
      "json",
      "--module",
      "manifest,execution,deps,intel",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      summary: { scannedFiles: number; totalFindings: number };
      results: Array<{ findings: Array<{ id: string }> }>;
    };

    expect(result.status).toBe(1);
    expect(result.stdout.trimStart().startsWith("{")).toBe(true);
    expect(result.stderr).toContain("Scanning directory:");
    expect(parsed.summary.scannedFiles).toBe(2);
    expect(parsed.summary.totalFindings).toBeGreaterThan(0);
    expect(parsed.results.flatMap((scan) => scan.findings.map((finding) => finding.id))).toContain(
      "GITHUB_SHA_EXECUTION",
    );
  });

  it("emits parseable recursive SARIF on stdout", async () => {
    const result = await runCli([
      "scan",
      batchDir,
      "--recursive",
      "--jobs",
      "2",
      "--output",
      "sarif",
      "--module",
      "manifest,execution,deps,intel",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      version: string;
      runs: Array<{ results: Array<{ ruleId: string }> }>;
    };

    expect(result.status).toBe(1);
    expect(result.stdout.trimStart().startsWith("{")).toBe(true);
    expect(result.stderr).toContain("Scanning directory:");
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs.flatMap((run) => run.results.map((finding) => finding.ruleId))).toContain(
      "GITHUB_SHA_EXECUTION",
    );
  });
});

describe("recursive scan failures", () => {
  let root = "";

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), "vsix-recursive-errors-"));
  });

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("returns exit code 2 when a clean archive succeeds and another archive fails", async () => {
    const directory = join(root, "mixed");
    await mkdir(directory);
    await writeFile(
      join(directory, "clean.vsix"),
      createTestZip([
        {
          name: "extension/package.json",
          content: JSON.stringify({ name: "clean", publisher: "test", version: "1.0.0" }),
        },
      ]),
    );
    await writeFile(join(directory, "broken.vsix"), "invalid ZIP");
    const result = await runCli([
      "scan",
      directory,
      "--recursive",
      "--module",
      "manifest",
      "--output",
      "json",
    ]);
    const batch = JSON.parse(result.stdout) as {
      summary: { scannedFiles: number; failedFiles: number };
    };
    expect(result.status).toBe(2);
    expect(batch.summary).toMatchObject({ scannedFiles: 1, failedFiles: 1 });
  });

  it.each(["1.5", "2junk", "0"])("rejects malformed recursive --jobs %s", async (jobs) => {
    const result = await runCli(["scan", root, "--recursive", "--jobs", jobs]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("positive safe integer");
  });
});
