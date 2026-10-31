#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const defaultManifestPath = join(repoRoot, "test-corpus", "clean", "manifest.json");
const defaultOutputDir = join(repoRoot, "test-corpus", "clean");
const cliPath = join(repoRoot, "dist", "index.js");

/** @param {string[]} argv */
function parseArgs(argv) {
  const options = {
    manifestPath: defaultManifestPath,
    outputDir: defaultOutputDir,
    force: false,
  };

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--manifest") {
      const value = argv.at(++index);
      if (value === undefined || value === "") throw new Error("--manifest requires a path");
      options.manifestPath = resolve(value);
    } else if (arg === "--output") {
      const value = argv.at(++index);
      if (value === undefined || value === "") throw new Error("--output requires a directory");
      options.outputDir = resolve(value);
    } else if (arg === "--force") {
      options.force = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

/** @param {string} path */
async function sha256File(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

/** @param {string} ref @param {string} outputDir @param {boolean} force */
async function runDownload(ref, outputDir, force) {
  const args = [cliPath, "download", ref, "--output", outputDir];
  if (force) args.push("--force");

  await new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (status) => {
      if (status === 0) {
        resolvePromise(undefined);
      } else {
        reject(new Error(`download failed for ${ref} with exit ${status}`));
      }
    });
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!existsSync(cliPath)) {
    throw new Error(`Built CLI not found at ${cliPath}. Run npm run build first.`);
  }

  const { validateCleanCorpusManifest, cleanCorpusFilename, cleanCorpusKey } =
    await import("#internal/scanner/clean-corpus.js");
  const { extensions } = validateCleanCorpusManifest(
    JSON.parse(await readFile(options.manifestPath, "utf8")),
  );
  await mkdir(options.outputDir, { recursive: true });

  for (const extension of extensions) {
    const filename = cleanCorpusFilename(extension);
    const outputPath = join(options.outputDir, filename);
    if (!options.force && existsSync(outputPath)) {
      const existingSha = await sha256File(outputPath);
      if (existingSha === extension.sha256) {
        console.log(`ok ${filename} ${extension.sha256}`);
        continue;
      }
      console.warn(`replacing ${filename}: sha256 mismatch ${existingSha}`);
    }

    await runDownload(cleanCorpusKey(extension), options.outputDir, options.force);

    const actualSha = await sha256File(outputPath);
    if (actualSha !== extension.sha256) {
      throw new Error(
        `${filename} sha256 mismatch: expected ${extension.sha256}, got ${actualSha}`,
      );
    }
    console.log(`ok ${filename} ${actualSha}`);
  }
}

try {
  await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
