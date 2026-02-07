export type Severity = "low" | "medium" | "high" | "critical";

export type Registry = "marketplace" | "openvsx" | "cursor";

export const MODULE_NAMES = ["package", "obfuscation", "ast", "ioc", "yara", "telemetry"] as const;
export type ModuleName = (typeof MODULE_NAMES)[number];

export interface ModuleTimings {
  load: number;
  total: number;
  [module: string]: number;
}

export interface ScanOptions {
  output: "text" | "json" | "sarif";
  severity: Severity;
  network: boolean;
  modules?: ModuleName[];
  profile?: boolean;
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
    timings?: ModuleTimings;
  };
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
  wallets: Set<string>;
  blockchainAllowlist: Set<string>;
  telemetryServices: Map<string, TelemetryServiceInfo>;
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
