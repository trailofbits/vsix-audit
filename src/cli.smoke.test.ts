import type { ScanResult } from "#internal/scanner/types.js";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateRawSync } from "node:zlib";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..");
const CLI_PATH = join(REPO_ROOT, "dist", "index.js");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createDeflatedZip(files: Array<{ name: string; content: string }>): Buffer {
  const chunks: Buffer[] = [];
  const centralDirEntries: Buffer[] = [];

  for (const file of files) {
    const localHeaderOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
    const content = Buffer.from(file.content, "utf8");
    const compressed = deflateRawSync(content);
    const fileName = Buffer.from(file.name, "utf8");
    const crc = crc32(content);

    const localHeader = Buffer.alloc(30 + fileName.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(8, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(content.length, 22);
    localHeader.writeUInt16LE(fileName.length, 26);
    localHeader.writeUInt16LE(0, 28);
    fileName.copy(localHeader, 30);
    chunks.push(localHeader, compressed);

    const cdEntry = Buffer.alloc(46 + fileName.length);
    cdEntry.writeUInt32LE(0x02014b50, 0);
    cdEntry.writeUInt16LE(20, 4);
    cdEntry.writeUInt16LE(20, 6);
    cdEntry.writeUInt16LE(0, 8);
    cdEntry.writeUInt16LE(8, 10);
    cdEntry.writeUInt16LE(0, 12);
    cdEntry.writeUInt16LE(0, 14);
    cdEntry.writeUInt32LE(crc, 16);
    cdEntry.writeUInt32LE(compressed.length, 20);
    cdEntry.writeUInt32LE(content.length, 24);
    cdEntry.writeUInt16LE(fileName.length, 28);
    cdEntry.writeUInt16LE(0, 30);
    cdEntry.writeUInt16LE(0, 32);
    cdEntry.writeUInt16LE(0, 34);
    cdEntry.writeUInt16LE(0, 36);
    cdEntry.writeUInt32LE(0, 38);
    cdEntry.writeUInt32LE(localHeaderOffset, 42);
    fileName.copy(cdEntry, 46);
    centralDirEntries.push(cdEntry);
  }

  const cdOffset = chunks.reduce((sum, buf) => sum + buf.length, 0);
  const cdSize = centralDirEntries.reduce((sum, buf) => sum + buf.length, 0);
  chunks.push(...centralDirEntries);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

async function runCli(
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<CliResult> {
  return await new Promise((resolvePromise, reject) => {
    const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" };
    delete env["VSIX_AUDIT_ZOO_PATH"];
    delete env["VSIX_AUDIT_CACHE_DIR"];
    Object.assign(env, options.env);

    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: options.cwd ?? REPO_ROOT,
      env,
    });

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
    child.on("close", (status) => {
      resolvePromise({ status, stdout, stderr });
    });
  });
}

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
      createDeflatedZip([
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
      createDeflatedZip([
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
      (JSON.parse(result.stdout) as ScanResult[]).map((scan) => scan.metadata.registry),
    ).toEqual(registries);
    expect(result.stderr).toContain("Downloading from marketplace:");
    expect(result.stderr).toContain("Downloading from openvsx:");
    expect(result.stderr).toContain("Downloading from cursor:");
    expect(result.stderr).not.toContain("Using cached");
    expect(await readdir(scanTempDir)).toEqual([]);
    await expectCacheUnchanged();
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
      createDeflatedZip([
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
      createDeflatedZip([
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
      createDeflatedZip([
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
      "package",
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
      "package",
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
      "package",
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
      "package",
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
      "package",
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
        "--no-network",
      ]);
      const parsed = JSON.parse(result.stdout) as ScanResult;
      expect(result.status).toBe(2);
      expect(parsed.metadata.coverage?.degraded).toBe(true);
      expect(parsed.metadata.coverage?.warnings).toEqual([expect.stringContaining('"main.js"')]);
    },
  );

  it("returns exit code 2 for strict coverage degradation", async () => {
    const result = await runCli([
      "scan",
      degradedVsix,
      "--output",
      "json",
      "--module",
      "package",
      "--strict",
    ]);
    const parsed = JSON.parse(result.stdout) as {
      findings: Array<{ id: string }>;
      metadata: { coverage?: { degraded?: boolean } };
    };

    expect(result.status).toBe(2);
    expect(parsed.metadata.coverage?.degraded).toBe(true);
    expect(parsed.findings.map((finding) => finding.id)).toContain(
      "ARCHIVE_REFERENCED_FILE_MISSING",
    );
  });

  it("returns exit code 2 when --require-yara excludes the yara module", async () => {
    const result = await runCli(["scan", cleanExtension, "--module", "package", "--require-yara"]);

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
      "package",
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
      "package",
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
      createDeflatedZip([
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
