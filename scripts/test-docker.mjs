import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** @typedef {import("#internal/scanner/types.js").ScanResult} ScanResult */
/** @typedef {import("#internal/scanner/types.js").BatchScanResult} BatchScanResult */

const image = process.argv[2] ?? "vsix-audit:test";
const packageInfo = /** @type {unknown} */ (
  JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"))
);
assert.ok(
  typeof packageInfo === "object" &&
    packageInfo !== null &&
    "version" in packageInfo &&
    typeof packageInfo.version === "string",
);
const { version } = packageInfo;
const nodeVersion = (await readFile(new URL("../.node-version", import.meta.url), "utf8")).trim();
const cache = fileURLToPath(new URL("../.cache/", import.meta.url));
await mkdir(cache, { recursive: true });
const fixtures = await mkdtemp(join(cache, "docker-"));
const runtimeOptions = [
  "--rm",
  "--network=none",
  "--read-only",
  "--tmpfs=/tmp:rw,noexec,nosuid,size=128m",
  "--cap-drop=ALL",
  "--security-opt=no-new-privileges",
  "--env=VSIX_AUDIT_CACHE_DIR=/tmp/vsix-audit-cache",
];

/** @param {string[]} args @param {number} [status] */
function docker(args, status = 0) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 120_000 });
  assert.ifError(result.error);
  assert.equal(
    result.status,
    status,
    `docker ${args.join(" ")}\n${result.stdout}\n${result.stderr}`,
  );
  return result.stdout;
}

/** @param {string[]} args @param {number} [status] */
function cli(args, status = 0) {
  return docker(
    [
      "run",
      ...runtimeOptions,
      "--mount",
      `type=bind,source=${fixtures},target=/fixtures,readonly`,
      image,
      ...args,
    ],
    status,
  );
}

/**
 * @param {string} name
 * @param {string} main
 * @param {Record<string, string>} [dependencies]
 */
async function writeExtension(name, main, dependencies = {}) {
  const directory = join(fixtures, "extensions", name);
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ name, publisher: "test", version: "1.0.0", main: "main.js", dependencies }),
  );
  await writeFile(join(directory, "main.js"), main);
}

/**
 * @param {string} name
 * @param {number} status
 * @param {import("#internal/scanner/types.js").Severity} [severity]
 */
function scan(name, status, severity = "low") {
  const output = cli(
    [
      "scan",
      `/fixtures/extensions/${name}`,
      "--output=json",
      "--no-cache",
      "--strict",
      "--require-yara",
      "--severity",
      severity,
    ],
    status,
  );
  const result = /** @type {ScanResult} */ (JSON.parse(output));
  assert.equal(result.metadata.coverage.degraded, false);
  assert.ok(result.inventory.every((check) => check.enabled));
  return result;
}

try {
  await chmod(fixtures, 0o755);
  await writeExtension("clean", 'console.log("hello");');
  await writeExtension(
    "behavior",
    await readFile(new URL("../test-corpus/behavior/source.txt", import.meta.url), "utf8"),
  );
  await writeExtension("suspicious", 'eval(atob("Y29uc29sZS5sb2coJ3Rlc3QnKQ=="));', {
    "vscode-darcula": "1.0.0",
  });

  assert.equal(cli(["--version"]).trim(), version);
  assert.equal(
    docker(["run", ...runtimeOptions, "--entrypoint=node", image, "--version"]).trim(),
    `v${nodeVersion}`,
  );
  assert.match(cli([]), /Usage: vsix-audit/);
  assert.match(
    docker(["run", ...runtimeOptions, "--entrypoint=yr", image, "--version"]),
    /^yara-x-cli /,
  );
  docker([
    "run",
    ...runtimeOptions,
    "--entrypoint=node",
    image,
    "--input-type=module",
    "-e",
    'import assert from "node:assert/strict"; assert.notEqual(process.getuid(), 0);',
  ]);

  assert.deepEqual(scan("clean", 0).findings, []);
  const behavior = scan("behavior", 0, "critical");
  assert.deepEqual(behavior.findings, []);
  assert.deepEqual(
    behavior.observations.map((item) => item.api),
    [
      "import",
      "import",
      "global.fetch",
      "fs.readFileSync",
      "fs.writeFileSync",
      "child_process.spawn",
      "global.eval",
    ],
  );
  const suspicious = scan("suspicious", 1);
  const ids = suspicious.findings.map((finding) => finding.id);
  assert.ok(ids.includes("AST_EVAL_DYNAMIC"), "Native AST parser must produce findings");
  assert.ok(ids.includes("MALICIOUS_NPM_PACKAGE"), "Bundled threat intelligence must load");
  assert.ok(
    suspicious.findings.some((finding) => finding.category === "yara"),
    "Bundled YARA rules must produce findings",
  );

  const installed = /** @type {BatchScanResult} */ (
    JSON.parse(
      cli(
        [
          "scan-installed",
          "--extensions-dir=/fixtures/extensions",
          "--output=json",
          "--strict",
          "--require-yara",
        ],
        1,
      ),
    )
  );
  assert.equal(installed.summary.scannedFiles, 3);
  assert.equal(
    installed.results.find((result) => result.extension.id === "test.behavior")?.observations
      .length,
    7,
  );
  assert.deepEqual(installed.errors, []);
  cli(["scan", "/fixtures/missing.vsix"], 2);
  console.log(`Docker smoke tests passed for ${image}`);
} finally {
  await rm(fixtures, { recursive: true, force: true });
}
