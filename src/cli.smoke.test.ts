import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

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

async function runCli(args: string[]): Promise<CliResult> {
  return await new Promise((resolvePromise, reject) => {
    const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" };
    delete env["VSIX_AUDIT_ZOO_PATH"];
    delete env["VSIX_AUDIT_CACHE_DIR"];

    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: REPO_ROOT,
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
    child.on("close", (status) => resolvePromise({ status, stdout, stderr }));
  });
}

describe("built CLI smoke tests", () => {
  let tempRoot = "";
  let cleanExtension = "";
  let suspiciousExtension = "";
  let degradedVsix = "";

  beforeAll(async () => {
    tempRoot = await mkdtemp(join(tmpdir(), "vsix-audit-cli-"));
    cleanExtension = join(tempRoot, "clean");
    suspiciousExtension = join(tempRoot, "suspicious");
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
});
