import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLEAN_CORPUS_MANIFEST = join(
  import.meta.dirname,
  "..",
  "..",
  "test-corpus",
  "clean",
  "manifest.json",
);

interface CleanCorpusEntry {
  id: string;
  publisher: string;
  name: string;
  version: string;
  registry: string;
  sha256: string;
  category: string;
  notes?: string;
}

interface CleanCorpusManifest {
  version: number;
  description: string;
  extensions: CleanCorpusEntry[];
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const REGISTRIES = new Set(["marketplace", "openvsx", "cursor"]);
const CATEGORIES = new Set(["baseline", "edge-case"]);

async function loadManifest(): Promise<CleanCorpusManifest> {
  return JSON.parse(await readFile(CLEAN_CORPUS_MANIFEST, "utf8")) as CleanCorpusManifest;
}

describe("clean corpus manifest", () => {
  it("pins valid benign extension artifacts", async () => {
    const manifest = await loadManifest();
    const seen = new Set<string>();

    expect(manifest.version).toBe(1);
    expect(manifest.description).toContain("false-positive");
    expect(manifest.extensions.length).toBeGreaterThan(0);

    for (const extension of manifest.extensions) {
      expect(extension.id).toBe(`${extension.publisher}.${extension.name}`);
      expect(extension.version).toMatch(VERSION_PATTERN);
      expect(extension.sha256).toMatch(SHA256_PATTERN);
      expect(REGISTRIES.has(extension.registry)).toBe(true);
      expect(CATEGORIES.has(extension.category)).toBe(true);
      expect(extension.notes?.length ?? 0).toBeGreaterThan(0);

      const key = `${extension.registry}:${extension.id}@${extension.version}`;
      expect(seen.has(key), `duplicate clean corpus entry ${key}`).toBe(false);
      seen.add(key);
    }
  });
});
