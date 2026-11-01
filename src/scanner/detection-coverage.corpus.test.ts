import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { checkHashes } from "#internal/scanner/checks/ioc.js";
import { isYaraAvailable } from "#internal/scanner/checks/yara.js";
import {
  cleanCorpusFilename,
  isNeverCleanFinding,
  validateCleanCorpusManifest,
  validateCleanCorpusCoverage,
} from "#internal/scanner/clean-corpus.js";
import { loadZooData } from "#internal/scanner/loaders/zoo.js";
import { scanExtension } from "#internal/scanner/index.js";
import type { ScanOptions } from "#internal/scanner/types.js";
import { loadExtension } from "#internal/scanner/vsix.js";

const CLEAN_DIR = resolve("test-corpus/clean");
const SAMPLES_DIR = resolve(process.env["VSIX_ZOO_PATH"] ?? ".cache/vsix-zoo/samples");
const TEAMPCP_NX_CONSOLE = "teampcp/nrwl.angular-console-18.95.0.vsix";
const manifest = validateCleanCorpusManifest(
  JSON.parse(readFileSync(join(CLEAN_DIR, "manifest.json"), "utf8")),
);
const options: ScanOptions = { output: "json", severity: "low", intel: "local" };

beforeAll(async () => {
  if (!(await isYaraAvailable()))
    throw new Error("Corpus tests require YARA-X; install yr before running npm run test:corpus.");
  for (const specimen of MALWARE_SAMPLES) {
    if (!existsSync(join(SAMPLES_DIR, specimen.path))) {
      throw new Error(
        `Missing required specimen ${specimen.path}; ` +
          "set VSIX_ZOO_PATH to the pinned vsix-zoo samples directory.",
      );
    }
  }
  for (const entry of manifest.extensions) {
    const file = join(CLEAN_DIR, cleanCorpusFilename(entry));
    if (!existsSync(file))
      throw new Error(`Missing required benign artifact ${file}; run npm run corpus:download.`);
  }
});

/**
 * Expected detections for each malware sample.
 * Maps sample path (relative to SAMPLES_DIR) to expected finding IDs.
 */
interface ExpectedDetection {
  path: string;
  description: string;
  scanOptions?: Partial<ScanOptions>;
  extension?: Record<string, unknown>;
  coverageWarnings?: string[];
  expectedFindings: {
    id: string;
    severity?: "low" | "medium" | "high" | "critical";
    metadata?: Record<string, unknown>;
    location?: { file: string };
    fileSuffix?: string;
  }[];
}

const MALWARE_SAMPLES: ExpectedDetection[] = [
  {
    path: "apollyon",
    extension: { name: "mal-vscode-poc", publisher: undefined },
    description: "Discord webhook exfiltration PoC",
    expectedFindings: [
      // Discord webhook YARA rule is high severity (per rule metadata)
      {
        id: "YARA_C2_JS_Discord_Webhook_Jan25",
        severity: "high",
        location: { file: "extension.js" },
      },
    ],
  },
  {
    path: "kagema/ShowSnowcrypto.SnowShoNo/showsnowcrypto.snowshono-0.6.0",
    extension: { publisher: "ShowSnowcrypto" },
    description: "SnowShoNo C2 malware",
    expectedFindings: [
      { id: "KNOWN_C2_DOMAIN", severity: "critical", metadata: { domain: "niggboo.com" } },
    ],
  },
  {
    path: "glassworm/icon-theme-materiall.vsix",
    description: "GlassWorm supply chain malware with Rust implant",
    expectedFindings: [
      { id: "BLOCKLIST_MATCH", severity: "critical" },
      {
        id: "KNOWN_MALWARE_HASH",
        severity: "critical",
        fileSuffix: "darwin.node",
      },
    ],
  },
  {
    path: "ecm3401/Extension-Attack-Suite",
    extension: { publisher: "ecm3401" },
    coverageWarnings: [
      "Manifest-referenced file is missing: out/extension.js (out/extension.js): " +
        "manifest main reference does not exist in the extension",
    ],
    description: "Educational attack suite with multiple techniques",
    expectedFindings: [
      { id: "KNOWN_MALWARE_HASH", severity: "critical" },
      { id: "BIDI_OVERRIDE", severity: "critical" },
      { id: "YARA_LOADER_PS_Download_Execute_Jan25", severity: "critical" },
    ],
  },
  {
    path: TEAMPCP_NX_CONSOLE,
    description: "Compromised TeamPCP Nx Console 18.95.0 extension",
    scanOptions: {
      modules: [
        "manifest",
        "execution",
        "deps",
        "intel",
        "obfuscation",
        "ast",
        "yara",
        "telemetry",
      ],
    },
    expectedFindings: [
      { id: "GITHUB_SHA_EXECUTION", severity: "critical" },
      { id: "BACKGROUND_TASK_EXECUTION", severity: "high" },
      { id: "STARTUP_EXECUTION_CHAIN", severity: "high" },
    ],
  },
];

describe("pinned malicious specimens", () => {
  it.each(MALWARE_SAMPLES)("preserves expected evidence in $path", async (specimen) => {
    const result = await scanExtension(join(SAMPLES_DIR, specimen.path), {
      ...options,
      ...specimen.scanOptions,
    });
    expect(specimen.expectedFindings.length).toBeGreaterThan(0);
    for (const { fileSuffix, ...expected } of specimen.expectedFindings) {
      const finding = result.findings.find(
        (candidate) =>
          candidate.id === expected.id &&
          (fileSuffix === undefined || candidate.location?.file.endsWith(fileSuffix) === true),
      );
      expect(finding).toMatchObject(expected);
    }
    expect(
      result.metadata.coverage.warnings.filter(
        (warning) =>
          !warning.includes("compiled format") && !warning.includes("native or compiled"),
      ),
    ).toEqual(specimen.coverageWarnings ?? []);
    expect(result.findings.map((finding) => finding.id)).not.toContain("YARA_NOT_INSTALLED");
    expect(result.observations.length).toBeGreaterThan(0);
    expect({ ...result.extension, publisher: result.extension.publisher }).toMatchObject(
      specimen.extension ?? {},
    );
  });

  it("retains generic Nx Console evidence with all threat intelligence disabled", async () => {
    const result = await scanExtension(join(SAMPLES_DIR, TEAMPCP_NX_CONSOLE), {
      ...options,
      intel: "none",
    });
    const ids = result.findings.map((finding) => finding.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        "GITHUB_SHA_EXECUTION",
        "BACKGROUND_TASK_EXECUTION",
        "STARTUP_EXECUTION_CHAIN",
      ]),
    );
    expect(
      ids.filter((id) =>
        ["KNOWN_MALWARE_HASH", "KNOWN_C2_DOMAIN", "KNOWN_C2_IP", "BLOCKLIST_MATCH"].includes(id),
      ),
    ).toEqual([]);
    expect(result.observations.length).toBeGreaterThan(0);
  });

  it("matches the pinned compromised Nx Console bundle hash", async () => {
    const [contents, data] = await Promise.all([
      loadExtension(join(SAMPLES_DIR, TEAMPCP_NX_CONSOLE)),
      loadZooData(),
    ]);
    expect(checkHashes(contents, data.hashes)).toContainEqual(
      expect.objectContaining({
        severity: "critical",
        location: { file: "main.js" },
        metadata: expect.objectContaining({
          sha256: "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74",
        }) as unknown,
      }),
    );
  });
});

describe("pinned benign artifacts", () => {
  it.each(manifest.extensions)(
    "retains observations without malware verdicts: $id@$version",
    async (entry) => {
      const file = join(CLEAN_DIR, cleanCorpusFilename(entry));
      expect(createHash("sha256").update(readFileSync(file)).digest("hex")).toBe(entry.sha256);
      const result = await scanExtension(file, options);
      expect(result.findings.filter(isNeverCleanFinding)).toEqual([]);
      expect(() => {
        validateCleanCorpusCoverage(entry, result.metadata.coverage);
      }).not.toThrow();
      const expectedModules: Record<string, string[]> = {
        "dbaeumer.vscode-eslint": ["child_process"],
      };
      const modules = result.observations
        .filter((item) => item.kind === "module-load")
        .map((item) => item.arguments[0])
        .filter((value) => value?.kind === "literal")
        .map((value) => value.value);
      expect(modules).toEqual(expect.arrayContaining(expectedModules[entry.id] ?? []));
    },
  );
});
