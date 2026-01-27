export type Severity = "low" | "medium" | "high" | "critical";

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

export interface ScanResult {
  extension: {
    id: string;
    name: string;
    version: string;
    publisher: string;
  };
  findings: Finding[];
  metadata: {
    scannedAt: string;
    scanDuration: number;
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
