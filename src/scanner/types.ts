export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;

export type OutputFormat = "text" | "json" | "sarif";

export const OUTPUT_FORMATS = ["text", "json", "sarif"] as const;

export type Registry = "marketplace" | "openvsx" | "cursor";

export const MODULE_NAMES = [
  "manifest",
  "execution",
  "deps",
  "intel",
  "obfuscation",
  "ast",
  "ioc",
  "yara",
  "telemetry",
  "repository",
] as const;
export type ModuleName = (typeof MODULE_NAMES)[number];

export type IntelMode = "local" | "none";

export const INTEL_MODES = ["local", "none"] as const;

export interface ModuleTimings {
  load: number;
  total: number;
  [module: string]: number;
}

export interface ScanOptions {
  output: OutputFormat;
  severity: Severity;
  modules?: ModuleName[];
  profile?: boolean;
  strict?: boolean;
  requireYara?: boolean;
  intel?: IntelMode;
  /** Verify declared source repositories over GitHub's API; disabled by default. */
  checkRepository?: boolean;
}

export interface FindingMetadata {
  matched?: string | undefined;
  matches?: YaraStringMatch[];
  totalMatches?: number;
  legitimateUses?: string[] | undefined;
  redFlags?: string[] | undefined;
  [key: string]: unknown;
}

export interface YaraStringMatch {
  identifier: string;
  offset: number;
  /** YARA-X's escaped excerpt, limited to 120 characters. */
  match: string;
}

export const CAPABILITY_NAMES = [
  "network",
  "execution",
  "fileAccess",
  "credentials",
  "obfuscation",
] as const;
export type Capability = (typeof CAPABILITY_NAMES)[number];

export type ObservationKind =
  | "network-request"
  | "network-client"
  | "file-read"
  | "file-write"
  | "process-execution"
  | "code-execution"
  | "module-load"
  | "credential-access"
  | "dynamic-call";

/** Statically available argument values; unresolved expressions are never evaluated. */
export type ObservedValue =
  | { kind: "literal"; value: string | number | boolean | null }
  | { kind: "array"; items: ObservedValue[] }
  | { kind: "object"; properties: Record<string, ObservedValue> }
  | { kind: "unresolved"; expression: string };

/** A source observation describes syntax, without asserting reachability or maliciousness. */
export interface Observation {
  kind: ObservationKind;
  capability: Capability;
  api: string;
  evidence: "call" | "import";
  arguments: ObservedValue[];
  /** Source excerpt, limited to 200 UTF-16 code units; the location retains the full span. */
  snippet: string;
  location: {
    file: string;
    /** One-based lines and UTF-16 columns, with an exclusive end. */
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    /** Zero-based UTF-16 offsets into the original source, with an exclusive end. */
    start: number;
    end: number;
  };
}

export interface Finding {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: string;
  readonly capabilities?: readonly Capability[];
  readonly location?: {
    readonly file: string;
    /** One-based line and UTF-16 column in text files. */
    readonly line?: number;
    readonly column?: number;
    /** Zero-based byte position, including for binary evidence. */
    readonly byteOffset?: number;
  };
  readonly metadata?: FindingMetadata;
}

export interface CheckResult {
  findings: Finding[];
  warnings: string[];
  observations?: Observation[];
}

export interface CheckSummary {
  readonly name: string;
  readonly enabled: boolean;
  readonly description: string;
  readonly filesExamined?: number;
  readonly rulesApplied?: number;
  readonly skipReason?: string;
}

export interface ScanResult {
  readonly extension: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly publisher?: string;
  };
  readonly findings: Finding[];
  /** Source facts retained independently of threat intelligence and severity filtering. */
  readonly observations: Observation[];
  readonly inventory: CheckSummary[];
  metadata: {
    scannedAt: string;
    scanDuration: number;
    /** Absolute source directory for an installed-extension scan. */
    sourcePath?: string;
    registry?: Registry;
    intel?: IntelMode;
    timings?: ModuleTimings;
    coverage: CoverageMetadata;
  };
}

export interface CoverageMetadata {
  degraded: boolean;
  warnings: string[];
  incompleteModules: ModuleName[];
}

export interface ArchiveWarning {
  id: string;
  title: string;
  message: string;
  severity: Severity;
  entryName: string;
  normalizedPath?: string;
  reason: string;
}

export interface ArtifactEntry {
  originalPath: string;
  path?: string;
  size: number;
  compressedSize?: number;
  uncompressedSize?: number;
  sha256?: string;
  skipped: boolean;
  skipReason?: string;
}

export interface PackageMetadata {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
}

export interface VsixManifest extends PackageMetadata {
  name: string;
  displayName?: string;
  publisher?: string;
  version: string;
  description?: string;
  main?: string;
  browser?: string;
  activationEvents?: string[];
  extensionDependencies?: string[];
  contributes?: {
    themes?: Array<{
      id?: string;
      label?: string;
      path?: string;
    }>;
    iconThemes?: Array<{
      id?: string;
      label?: string;
      path?: string;
    }>;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface VsixContents {
  manifest: VsixManifest;
  files: Map<string, Buffer>;
  basePath: string;
  archiveWarnings?: ArchiveWarning[];
  artifacts?: ArtifactEntry[];
  /** Pre-computed UTF-8 string contents, keyed by filename */
  stringContents?: Map<string, string>;
}

export interface BlocklistEntry {
  id: string;
  name: string;
  reason: string;
  campaign?: string;
  platform?: string;
  addedDate?: string;
  reference?: string;
}

export interface MaliciousNpmVersionAdvisory {
  name: string;
  affectedVersions: string[];
  advisory: string;
  reason: string;
  campaign?: string;
  references?: string[];
}

export type TelemetryCategory = "analytics" | "crash-reporting" | "apm";

export interface TelemetryServiceInfo {
  name: string;
  category: TelemetryCategory;
  domains: string[];
}

export interface ZooData {
  blocklist: BlocklistEntry[];
  hashes: Set<string>;
  domains: Set<string>;
  ips: Set<string>;
  maliciousNpmPackages: Set<string>;
  maliciousNpmVersions: Map<string, MaliciousNpmVersionAdvisory[]>;
  wallets: Set<string>;
  blockchainAllowlist: Set<string>;
  telemetryServices: Map<string, TelemetryServiceInfo>;
  githubC2Accounts: Set<string>;
}

export interface BatchScanResult {
  results: ScanResult[];
  errors: Array<{ path: string; error: string }>;
  /** Searched stores and inventory scope for installed scans, including failed discovery. */
  discovery?: InstalledScanScope;
  summary: {
    totalFiles: number;
    scannedFiles: number;
    failedFiles: number;
    totalFindings: number;
    findingsBySeverity: Record<Severity, number>;
    scanDuration: number;
  };
}

export interface InstalledScanScope {
  roots: string[];
  scope: string;
}
