export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;

export type OutputFormat = "text" | "json" | "sarif";

export const OUTPUT_FORMATS = ["text", "json", "sarif"] as const;

export type Registry = "marketplace" | "openvsx" | "cursor";

export const MODULE_NAMES = [
  "package",
  "manifest",
  "execution",
  "deps",
  "intel",
  "obfuscation",
  "ast",
  "ioc",
  "yara",
  "telemetry",
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
  network: boolean;
  modules?: ModuleName[];
  profile?: boolean;
  strict?: boolean;
  requireYara?: boolean;
  intel?: IntelMode;
}

export interface FindingMetadata {
  matched?: string | undefined;
  legitimateUses?: string[] | undefined;
  redFlags?: string[] | undefined;
  [key: string]: unknown;
}

export interface Finding {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: string;
  readonly location?: {
    readonly file: string;
    readonly line?: number;
    readonly column?: number;
  };
  readonly metadata?: FindingMetadata;
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
    readonly publisher: string;
  };
  readonly findings: Finding[];
  readonly inventory: CheckSummary[];
  metadata: {
    scannedAt: string;
    scanDuration: number;
    registry?: Registry;
    intel?: IntelMode;
    timings?: ModuleTimings;
    coverage?: CoverageMetadata;
  };
}

export interface CoverageMetadata {
  degraded: boolean;
  warnings: string[];
  unavailableModules?: ModuleName[];
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

export interface VsixManifest {
  name: string;
  displayName?: string;
  publisher: string;
  version: string;
  description?: string;
  main?: string;
  browser?: string;
  activationEvents?: string[];
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
  warnings?: string[];
  archiveWarnings?: ArchiveWarning[];
  artifacts?: ArtifactEntry[];
  /** Pre-computed UTF-8 string contents, keyed by filename */
  stringContents?: Map<string, string>;
  /** Shared cache for memoized per-file computations */
  cache?: Map<string, unknown>;
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
  summary: {
    totalFiles: number;
    scannedFiles: number;
    failedFiles: number;
    totalFindings: number;
    findingsBySeverity: Record<Severity, number>;
    scanDuration: number;
  };
}
