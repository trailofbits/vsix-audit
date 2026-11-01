import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  cleanCorpusKey,
  isNeverCleanFinding,
  validateCleanCorpusManifest,
  validateCleanCorpusCoverage,
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
  it.each(["complete", "missing warning", "extra warning", "wrong module", "wrong status"])(
    "validates an annotated compiled-file exception: %s",
    async (variation) => {
      const entry = validateCleanCorpusManifest(await loadManifest()).extensions[0];
      if (entry === undefined) throw new Error("Missing pinned fixture");
      const warnings = [
        'Limited analysis of "runtime.wasm": native or compiled code is outside the script analyzers.',
        'YARA-X skipped "runtime.wasm": the bundled script rules do not analyze this compiled format.',
      ];
      const actualWarnings =
        variation === "missing warning"
          ? warnings.slice(0, 1)
          : variation === "extra warning"
            ? [...warnings, "Unexpected parser failure"]
            : warnings;
      const check = (): void => {
        validateCleanCorpusCoverage(
          { ...entry, unanalyzedFiles: ["runtime.wasm"] },
          {
            degraded: variation !== "wrong status",
            warnings: actualWarnings,
            incompleteModules: variation === "wrong module" ? ["ast"] : ["yara"],
          },
        );
      };
      let failure: unknown;
      try {
        check();
      } catch (error) {
        failure = error;
      }
      const message = failure instanceof Error ? failure.message : undefined;
      expect(message).toBe(
        variation === "complete"
          ? undefined
          : `${entry.id}: unexpected scan coverage; inspect coverage diagnostics and ` +
              "restore the required analyzers before accepting this corpus result.",
      );
    },
  );
  it.each([null, "file.wasm", [false], [""]])(
    "rejects invalid compiled-file annotations: %j",
    async (unanalyzedFiles) => {
      const source = (await loadManifest()) as { extensions: Array<Record<string, unknown>> };
      if (source.extensions[0] === undefined) throw new Error("Missing pinned fixture");
      source.extensions[0]["unanalyzedFiles"] = unanalyzedFiles;
      expect(() => validateCleanCorpusManifest(source)).toThrow("unanalyzedFiles");
    },
  );

  it("rejects missing analyzers even when the finding list is empty", async () => {
    const entry = validateCleanCorpusManifest(await loadManifest()).extensions[0];
    if (entry === undefined) throw new Error("Missing pinned fixture");
    expect(() => {
      validateCleanCorpusCoverage(entry, {
        degraded: true,
        warnings: ["YARA-X not installed"],
        incompleteModules: ["yara"],
      });
    }).toThrow("unexpected scan coverage");
    expect(() => {
      validateCleanCorpusCoverage(entry, { degraded: false, warnings: [], incompleteModules: [] });
    }).not.toThrow();
  });
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
