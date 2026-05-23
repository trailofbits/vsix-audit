export interface CleanCorpusEntry {
  id: string;
  publisher: string;
  name: string;
  version: string;
  registry: "marketplace" | "openvsx" | "cursor";
  sha256: string;
  category: "baseline" | "edge-case";
  notes?: string;
}

export interface CleanCorpusManifest {
  version: 1;
  description: string;
  extensions: CleanCorpusEntry[];
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const REGISTRIES = new Set(["marketplace", "openvsx", "cursor"]);
const CATEGORIES = new Set(["baseline", "edge-case"]);

export const CLEAN_CORPUS_NEVER_FINDINGS = new Set([
  "BLOCKLIST_MATCH",
  "KNOWN_MALWARE_HASH",
  "KNOWN_C2_DOMAIN",
  "KNOWN_C2_IP",
  "KNOWN_GITHUB_C2",
  "KNOWN_MALWARE_WALLET",
  "MALICIOUS_NPM_PACKAGE",
  "MALICIOUS_NPM_PACKAGE_VERSION",
  "ARCHIVE_INVALID_PATH",
  "ARCHIVE_PORTABLE_PATH_COLLISION",
  "ARCHIVE_DUPLICATE_PATH",
  "ARCHIVE_SKIPPED_ENTRY",
  "ARCHIVE_REFERENCED_FILE_MISSING",
  "ARCHIVE_REFERENCED_FILE_SKIPPED",
  "ARCHIVE_INVALID_MANIFEST_REFERENCE",
  "INVISIBLE_CODE_EXECUTION",
  "VARIATION_SELECTOR",
  "YARA_LOADER_JS_Download_Write_Execute_Jan25",
  "YARA_RAT_JS_GlassWorm_Remote_Exec_Jan25",
  "YARA_STEALER_JS_Credential_File_Exfil_Jan25",
  "YARA_STEALER_JS_Env_Token_Exfil_Jan25",
  "YARA_SUSP_JS_Eval_Base64_Jan25",
  "YARA_SUSP_JS_Eval_Charcode_Jan25",
  "YARA_SUSP_JS_Obfuscation_Eval_Jan25",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, field: string, extensionId: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${extensionId}: missing or invalid ${field}`);
  }
  return value;
}

function validateEntry(value: unknown): CleanCorpusEntry {
  if (!isRecord(value)) {
    throw new Error("Invalid extension entry in clean corpus manifest");
  }

  const id = requireString(value["id"], "id", "<unknown>");
  const publisher = requireString(value["publisher"], "publisher", id);
  const name = requireString(value["name"], "name", id);
  const version = requireString(value["version"], "version", id);
  const registry = requireString(value["registry"], "registry", id);
  const sha256 = requireString(value["sha256"], "sha256", id);
  const category = requireString(value["category"], "category", id);
  const notes = typeof value["notes"] === "string" ? value["notes"] : undefined;

  if (id !== `${publisher}.${name}`) {
    throw new Error(`${id}: id must equal publisher.name`);
  }
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`${id}: version must be pinned to a concrete semver version`);
  }
  if (!REGISTRIES.has(registry)) {
    throw new Error(`${id}: unsupported registry "${registry}"`);
  }
  if (!SHA256_PATTERN.test(sha256)) {
    throw new Error(`${id}: sha256 must be 64 lowercase hex characters`);
  }
  if (!CATEGORIES.has(category)) {
    throw new Error(`${id}: unsupported category "${category}"`);
  }

  return {
    id,
    publisher,
    name,
    version,
    registry: registry as CleanCorpusEntry["registry"],
    sha256,
    category: category as CleanCorpusEntry["category"],
    ...(notes !== undefined ? { notes } : {}),
  };
}

export function validateCleanCorpusManifest(value: unknown): CleanCorpusManifest {
  if (!isRecord(value)) {
    throw new Error("Clean corpus manifest must be an object");
  }
  if (value["version"] !== 1) {
    throw new Error("Clean corpus manifest version must be 1");
  }
  if (typeof value["description"] !== "string" || value["description"].length === 0) {
    throw new Error("Clean corpus manifest must include a description");
  }
  if (!Array.isArray(value["extensions"])) {
    throw new Error("Clean corpus manifest must contain an extensions array");
  }

  const seen = new Set<string>();
  const extensions = value["extensions"].map((entry: unknown) => {
    const extension = validateEntry(entry);
    const key = cleanCorpusKey(extension);
    if (seen.has(key)) {
      throw new Error(`Duplicate clean corpus entry: ${key}`);
    }
    seen.add(key);
    return extension;
  });

  return {
    version: 1,
    description: value["description"],
    extensions,
  };
}

export function cleanCorpusKey(extension: CleanCorpusEntry): string {
  return `${extension.registry}:${extension.id}@${extension.version}`;
}

export function cleanCorpusFilename(extension: CleanCorpusEntry): string {
  return `${extension.publisher}.${extension.name}-${extension.version}.vsix`;
}

export function isNeverCleanFindingId(findingId: string): boolean {
  return CLEAN_CORPUS_NEVER_FINDINGS.has(findingId);
}
