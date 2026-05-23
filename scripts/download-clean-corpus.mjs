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

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const VALID_REGISTRIES = new Set(["marketplace", "openvsx", "cursor"]);
const VALID_CATEGORIES = new Set(["baseline", "edge-case"]);

function parseArgs(argv) {
  const options = {
    manifestPath: defaultManifestPath,
    outputDir: defaultOutputDir,
    force: false,
  };

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--manifest") {
      const value = argv[++index];
      if (!value) throw new Error("--manifest requires a path");
      options.manifestPath = resolve(value);
    } else if (arg === "--output") {
      const value = argv[++index];
      if (!value) throw new Error("--output requires a directory");
      options.outputDir = resolve(value);
    } else if (arg === "--force") {
      options.force = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return options;
}

function assertString(value, field, extensionId) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${extensionId}: missing or invalid ${field}`);
  }
  return value;
}

function validateExtension(extension) {
  if (!extension || typeof extension !== "object" || Array.isArray(extension)) {
    throw new Error("Invalid extension entry in clean corpus manifest");
  }

  const id = assertString(extension.id, "id", "<unknown>");
  const publisher = assertString(extension.publisher, "publisher", id);
  const name = assertString(extension.name, "name", id);
  const version = assertString(extension.version, "version", id);
  const registry = assertString(extension.registry, "registry", id);
  const sha256 = assertString(extension.sha256, "sha256", id);
  const category = assertString(extension.category, "category", id);

  if (id !== `${publisher}.${name}`) {
    throw new Error(`${id}: id must equal publisher.name`);
  }
  if (!VALID_REGISTRIES.has(registry)) {
    throw new Error(`${id}: unsupported registry "${registry}"`);
  }
  if (!SHA256_PATTERN.test(sha256)) {
    throw new Error(`${id}: sha256 must be 64 lowercase hex characters`);
  }
  if (!VALID_CATEGORIES.has(category)) {
    throw new Error(`${id}: unsupported category "${category}"`);
  }

  return { id, publisher, name, version, registry, sha256, category };
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("Clean corpus manifest must be an object");
  }
  if (manifest.version !== 1) {
    throw new Error("Clean corpus manifest version must be 1");
  }
  if (!Array.isArray(manifest.extensions)) {
    throw new Error("Clean corpus manifest must contain an extensions array");
  }

  const seen = new Set();
  return manifest.extensions.map((entry) => {
    const extension = validateExtension(entry);
    const key = `${extension.registry}:${extension.id}@${extension.version}`;
    if (seen.has(key)) {
      throw new Error(`Duplicate clean corpus entry: ${key}`);
    }
    seen.add(key);
    return extension;
  });
}

async function sha256File(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

function expectedFilename(extension) {
  return `${extension.publisher}.${extension.name}-${extension.version}.vsix`;
}

function extensionRef(extension) {
  return `${extension.registry}:${extension.id}@${extension.version}`;
}

async function runDownload(extension, outputDir, force) {
  const args = [cliPath, "download", extensionRef(extension), "--output", outputDir];
  if (force) args.push("--force");

  await new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (status) => {
      if (status === 0) {
        resolvePromise();
      } else {
        reject(new Error(`download failed for ${extensionRef(extension)} with exit ${status}`));
      }
    });
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!existsSync(cliPath)) {
    throw new Error(`Built CLI not found at ${cliPath}. Run npm run build first.`);
  }

  const manifest = JSON.parse(await readFile(options.manifestPath, "utf8"));
  const extensions = validateManifest(manifest);
  await mkdir(options.outputDir, { recursive: true });

  for (const extension of extensions) {
    const outputPath = join(options.outputDir, expectedFilename(extension));
    if (!options.force && existsSync(outputPath)) {
      const existingSha = await sha256File(outputPath);
      if (existingSha === extension.sha256) {
        console.log(`ok ${expectedFilename(extension)} ${extension.sha256}`);
        continue;
      }
      console.warn(`replacing ${expectedFilename(extension)}: sha256 mismatch ${existingSha}`);
    }

    await runDownload(extension, options.outputDir, options.force);

    const actualSha = await sha256File(outputPath);
    if (actualSha !== extension.sha256) {
      throw new Error(
        `${expectedFilename(extension)} sha256 mismatch: expected ${extension.sha256}, got ${actualSha}`,
      );
    }
    console.log(`ok ${expectedFilename(extension)} ${actualSha}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
