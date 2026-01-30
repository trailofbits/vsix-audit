export type Severity = "low" | "medium" | "high" | "critical";

export type Registry = "marketplace" | "openvsx";

export interface ScanOptions {
  output: "text" | "json" | "sarif";
  severity: Severity;
  network: boolean;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  location?: {
    file: string;
    line?: number;
    column?: number;
  };
  metadata?: Record<string, unknown>;
}

export interface CheckSummary {
  name: string;
  enabled: boolean;
  description: string;
  filesExamined?: number;
  rulesApplied?: number;
  skipReason?: string;
}

export interface ScanResult {
  extension: {
    id: string;
    name: string;
    version: string;
    publisher: string;
  };
  findings: Finding[];
  inventory: CheckSummary[];
  metadata: {
    scannedAt: string;
    scanDuration: number;
    registry?: Registry;
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

export interface ZooData {
  blocklist: BlocklistEntry[];
  hashes: Set<string>;
  domains: Set<string>;
  ips: Set<string>;
  maliciousNpmPackages: Set<string>;
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
