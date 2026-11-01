import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  cleanCorpusKey,
  isNeverCleanFinding,
  validateCleanCorpusManifest,
} from "#internal/scanner/clean-corpus.js";

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
  it("rejects critical findings from rules that are not in a fixed identifier list", () => {
    expect(isNeverCleanFinding({ id: "NEW_RULE", severity: "critical" })).toBe(true);
    expect(
      isNeverCleanFinding({ id: "YARA_SUSP_JS_Eval_Base64_Jan25", severity: "critical" }),
    ).toBe(true);
    expect(isNeverCleanFinding({ id: "YARA_SUSP_JS_Eval_Base64_Jan25", severity: "medium" })).toBe(
      false,
    );
  });
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
    expect(isNeverCleanFinding({ id: "KNOWN_MALWARE_HASH", severity: "high" })).toBe(true);
    expect(isNeverCleanFinding({ id: "KNOWN_GITHUB_C2", severity: "high" })).toBe(true);
    expect(isNeverCleanFinding({ id: "BIDI_OVERRIDE", severity: "high" })).toBe(true);
    expect(isNeverCleanFinding({ id: "ARCHIVE_PORTABLE_PATH_COLLISION", severity: "high" })).toBe(
      true,
    );
    expect(isNeverCleanFinding({ id: "ARCHIVE_DUPLICATE_PATH", severity: "high" })).toBe(true);
    expect(isNeverCleanFinding({ id: "ARCHIVE_REFERENCED_FILE_MISSING", severity: "high" })).toBe(
      true,
    );
    expect(
      isNeverCleanFinding({
        id: "YARA_STEALER_JS_Credential_File_Exfil_Jan25",
        severity: "medium",
      }),
    ).toBe(false);

    expect(isNeverCleanFinding({ id: "ARCHIVE_PATH_COLLISION", severity: "high" })).toBe(false);
    expect(isNeverCleanFinding({ id: "ARCHIVE_DUPLICATE_ENTRY", severity: "high" })).toBe(false);
    expect(isNeverCleanFinding({ id: "STARTUP_EXECUTION_CHAIN", severity: "high" })).toBe(false);
    expect(isNeverCleanFinding({ id: "ACTIVATION_STARTUP", severity: "high" })).toBe(false);
    expect(isNeverCleanFinding({ id: "AST_DYNAMIC_IMPORT", severity: "high" })).toBe(false);
    expect(
      isNeverCleanFinding({ id: "YARA_SUSP_JS_Child_Process_Variable_Jan25", severity: "high" }),
    ).toBe(false);
  });
});
