import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  cleanCorpusKey,
  isNeverCleanFindingId,
  validateCleanCorpusManifest,
} from "./clean-corpus.js";

const CLEAN_CORPUS_MANIFEST = join(
  import.meta.dirname,
  "..",
  "..",
  "test-corpus",
  "clean",
  "manifest.json",
);

async function loadManifest(): Promise<unknown> {
  return JSON.parse(await readFile(CLEAN_CORPUS_MANIFEST, "utf8")) as unknown;
}

describe("clean corpus manifest", () => {
  it("pins valid benign extension artifacts", async () => {
    const manifest = validateCleanCorpusManifest(await loadManifest());
    const seen = new Set<string>();

    expect(manifest.version).toBe(1);
    expect(manifest.description).toContain("false-positive");
    expect(manifest.extensions.length).toBeGreaterThan(0);

    for (const extension of manifest.extensions) {
      expect(extension.id).toBe(`${extension.publisher}.${extension.name}`);
      expect(extension.notes?.length ?? 0).toBeGreaterThan(0);

      const key = cleanCorpusKey(extension);
      expect(seen.has(key), `duplicate clean corpus entry ${key}`).toBe(false);
      seen.add(key);
    }
  });

  it("keeps generic heuristic noise out of the never-in-clean gate", () => {
    expect(isNeverCleanFindingId("KNOWN_MALWARE_HASH")).toBe(true);
    expect(isNeverCleanFindingId("ARCHIVE_REFERENCED_FILE_MISSING")).toBe(true);
    expect(isNeverCleanFindingId("YARA_STEALER_JS_Credential_File_Exfil_Jan25")).toBe(true);

    expect(isNeverCleanFindingId("STARTUP_EXECUTION_CHAIN")).toBe(false);
    expect(isNeverCleanFindingId("ACTIVATION_STARTUP")).toBe(false);
    expect(isNeverCleanFindingId("AST_DYNAMIC_IMPORT")).toBe(false);
    expect(isNeverCleanFindingId("BIDI_OVERRIDE")).toBe(false);
    expect(isNeverCleanFindingId("YARA_SUSP_JS_Child_Process_Variable_Jan25")).toBe(false);
  });
});
