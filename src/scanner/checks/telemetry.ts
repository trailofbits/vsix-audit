import { isScannable, SCANNABLE_EXTENSIONS_PATTERN } from "../constants.js";
import type {
  Finding,
  TelemetryCategory,
  TelemetryServiceInfo,
  VsixContents,
  VsixManifest,
  ZooData,
} from "../types.js";
import { findLineNumberByString } from "../utils.js";

/**
 * Known telemetry SDK packages and their service info.
 */
const TELEMETRY_SDKS: Record<string, { name: string; category: TelemetryCategory }> = {
  // Crash reporting
  "@sentry/node": { name: "Sentry", category: "crash-reporting" },
  "@sentry/browser": { name: "Sentry", category: "crash-reporting" },
  "@sentry/react": { name: "Sentry", category: "crash-reporting" },
  "@sentry/vue": { name: "Sentry", category: "crash-reporting" },
  bugsnag: { name: "Bugsnag", category: "crash-reporting" },
  "@bugsnag/js": { name: "Bugsnag", category: "crash-reporting" },
  "@bugsnag/node": { name: "Bugsnag", category: "crash-reporting" },
  rollbar: { name: "Rollbar", category: "crash-reporting" },
  raygun4js: { name: "Raygun", category: "crash-reporting" },

  // Analytics
  mixpanel: { name: "Mixpanel", category: "analytics" },
  "mixpanel-browser": { name: "Mixpanel", category: "analytics" },
  "@amplitude/node": { name: "Amplitude", category: "analytics" },
  "@amplitude/analytics-browser": { name: "Amplitude", category: "analytics" },
  "@segment/analytics-node": { name: "Segment", category: "analytics" },
  "analytics-node": { name: "Segment", category: "analytics" },
  "@segment/analytics-next": { name: "Segment", category: "analytics" },
  "posthog-node": { name: "PostHog", category: "analytics" },
  "posthog-js": { name: "PostHog", category: "analytics" },
  heap: { name: "Heap", category: "analytics" },
  "heap-api": { name: "Heap", category: "analytics" },

  // APM
  applicationinsights: { name: "Azure Application Insights", category: "apm" },
  "dd-trace": { name: "Datadog", category: "apm" },
  newrelic: { name: "New Relic", category: "apm" },

  // VS Code specific
  "@vscode/extension-telemetry": { name: "VS Code Telemetry", category: "analytics" },
  "vscode-extension-telemetry": { name: "VS Code Telemetry", category: "analytics" },
};

/**
 * Patterns that indicate telemetry URL paths.
 * These patterns are conservative - we want to match actual API endpoints, not docs.
 */
const TELEMETRY_URL_PATTERNS = [
  /\/api\/telemetry/i,
  /\/v\d+\/track\b/i,
  /\/collect(?:\/v\d+)?$/i, // /collect or /collect/v1 at end of path
  /\/ingest\b/i,
  /\/metrics$/i, // /metrics at end of path
];

/**
 * Domains that are known documentation sites, not telemetry endpoints.
 * URLs from these domains should not trigger unknown telemetry detection.
 */
const DOCUMENTATION_DOMAINS = new Set([
  "nodejs.org",
  "developer.mozilla.org",
  "docs.github.com",
  "source.chromium.org",
  "github.com",
  "stackoverflow.com",
  "wikipedia.org",
  "w3.org",
  "tc39.es",
  "ecma-international.org",
  "typescriptlang.org",
  "reactjs.org",
  "vuejs.org",
  "angular.io",
]);

/**
 * Data fields commonly collected by telemetry.
 */
const DATA_COLLECTION_PATTERNS: Array<{ pattern: RegExp; field: string }> = [
  { pattern: /extension[_-]?version/i, field: "extension_version" },
  { pattern: /vscode[_-]?version/i, field: "vscode_version" },
  { pattern: /os[_-]?platform/i, field: "os_platform" },
  { pattern: /os[_-]?version/i, field: "os_version" },
  { pattern: /machine[_-]?id/i, field: "machine_id" },
  { pattern: /session[_-]?id/i, field: "session_id" },
  { pattern: /user[_-]?id/i, field: "user_id" },
  { pattern: /workspace[_-]?info/i, field: "workspace_info" },
  { pattern: /file[_-]?paths?/i, field: "file_paths" },
  { pattern: /user[_-]?behavior/i, field: "user_behavior" },
  { pattern: /language[_-]?id/i, field: "language_id" },
  { pattern: /activation[_-]?event/i, field: "activation_event" },
  { pattern: /command[_-]?id/i, field: "command_id" },
  { pattern: /error[_-]?stack/i, field: "error_stack" },
  { pattern: /performance[_-]?metrics/i, field: "performance_metrics" },
];

type OptOutMethod = "vscode-api" | "manifest-config" | "code-conditional" | "none";

interface OptOutInfo {
  available: boolean;
  method: OptOutMethod;
  settingName: string | null;
}

interface TelemetryDetection {
  serviceName: string;
  serviceCategory: TelemetryCategory;
  endpoint: string | null;
  sdkPackage: string | null;
  isKnownService: boolean;
  dataCollected: string[];
  optOut: OptOutInfo;
  file: string;
  line: number | undefined;
}

/**
 * Extract URLs from code content.
 */
function extractUrls(content: string): Array<{ url: string; index: number }> {
  const urlPattern = /https?:\/\/[^\s"'`<>\])}]+/gi;
  const results: Array<{ url: string; index: number }> = [];

  for (const match of content.matchAll(urlPattern)) {
    if (match.index !== undefined) {
      results.push({ url: match[0], index: match.index });
    }
  }

  return results;
}

/**
 * Extract domain from a URL.
 */
function extractDomain(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Check if a domain is a known documentation site.
 */
function isDocumentationDomain(domain: string): boolean {
  // Check exact match
  if (DOCUMENTATION_DOMAINS.has(domain)) return true;

  // Check if it's a subdomain of a documentation domain
  for (const docDomain of DOCUMENTATION_DOMAINS) {
    if (domain.endsWith(`.${docDomain}`)) return true;
  }

  return false;
}

/**
 * Check if a URL looks like documentation rather than an API endpoint.
 * This helps filter out false positives from known telemetry service domains.
 */
function isDocumentationUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();

    // Documentation paths
    if (path.includes("/docs/")) return true;
    if (path.includes("/documentation/")) return true;
    if (path.includes("/blog/")) return true;
    if (path.includes("/guide/")) return true;
    if (path.includes("/tutorial/")) return true;
    if (path.includes("/help/")) return true;
    if (path.includes("/support/")) return true;
    if (path.includes("/faq/")) return true;

    // HTML pages are usually documentation, not API endpoints
    if (path.endsWith(".html")) return true;
    if (path.endsWith(".htm")) return true;

    // Marketing/info/UI pages
    if (path.includes("/home")) return true;
    if (path.includes("/organizations")) return true;
    if (path.includes("/billing/")) return true;
    if (path.includes("/settings/")) return true;
    if (path.includes("/projects/")) return true;

    return false;
  } catch {
    return false;
  }
}

/**
 * Check if a URL path matches telemetry patterns.
 */
function isTelemetryPath(url: string): boolean {
  try {
    const parsed = new URL(url);

    // Skip documentation domains
    const domain = parsed.hostname.toLowerCase();
    if (isDocumentationDomain(domain)) return false;

    return TELEMETRY_URL_PATTERNS.some((pattern) => pattern.test(parsed.pathname));
  } catch {
    return false;
  }
}

/**
 * Detect SDK imports in code (both ESM and CommonJS).
 */
function detectSdkImports(
  content: string,
): Array<{ pkg: string; info: { name: string; category: TelemetryCategory }; index: number }> {
  const results: Array<{
    pkg: string;
    info: { name: string; category: TelemetryCategory };
    index: number;
  }> = [];

  // ESM: import ... from "package"
  const esmPattern = /import\s+(?:[\w{},\s*]+\s+from\s+)?["']([^"']+)["']/g;
  for (const match of content.matchAll(esmPattern)) {
    const pkg = match[1];
    if (pkg && TELEMETRY_SDKS[pkg]) {
      const info = TELEMETRY_SDKS[pkg];
      if (info) {
        results.push({ pkg, info, index: match.index ?? 0 });
      }
    }
  }

  // CommonJS: require("package")
  const cjsPattern = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const match of content.matchAll(cjsPattern)) {
    const pkg = match[1];
    if (pkg && TELEMETRY_SDKS[pkg]) {
      const info = TELEMETRY_SDKS[pkg];
      if (info) {
        results.push({ pkg, info, index: match.index ?? 0 });
      }
    }
  }

  return results;
}

/**
 * Detect VS Code API opt-out usage.
 */
function detectVsCodeApiOptOut(content: string): boolean {
  // vscode.env.isTelemetryEnabled
  return /vscode\.env\.isTelemetryEnabled/i.test(content);
}

/**
 * Detect code conditional opt-out patterns.
 */
function detectCodeConditionalOptOut(content: string): {
  found: boolean;
  settingName: string | null;
} {
  // Common patterns for configuration-based opt-out
  const patterns = [
    /getConfiguration\s*\([^)]*\)\s*\.\s*get\s*\(\s*["']([^"']*telemetry[^"']*)["']/i,
    /getConfiguration\s*\(\s*["']([^"']+)["']\s*\)\s*\.\s*get\s*\(\s*["']([^"']*enable[^"']*)["']/i,
    /config\s*\.\s*get\s*\(\s*["']([^"']*telemetry[^"']*)["']/i,
  ];

  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) {
      return { found: true, settingName: match[1] ?? match[2] ?? null };
    }
  }

  return { found: false, settingName: null };
}

/**
 * Check manifest for telemetry configuration settings.
 */
function detectManifestOptOut(manifest: VsixManifest): {
  found: boolean;
  settingName: string | null;
} {
  const contributes = manifest.contributes;
  if (!contributes) return { found: false, settingName: null };

  const configuration = contributes["configuration"];
  if (!configuration) return { found: false, settingName: null };

  // configuration can be an object or array
  const configs = Array.isArray(configuration) ? configuration : [configuration];

  for (const config of configs) {
    if (typeof config !== "object" || !config) continue;

    const properties = (config as { properties?: Record<string, unknown> }).properties;
    if (!properties) continue;

    for (const [key, _value] of Object.entries(properties)) {
      const keyLower = key.toLowerCase();
      if (
        keyLower.includes("telemetry") ||
        keyLower.includes("analytics") ||
        keyLower.includes("tracking")
      ) {
        return { found: true, settingName: key };
      }
    }
  }

  return { found: false, settingName: null };
}

/**
 * Detect data collection patterns near a given position in the code.
 */
function detectDataCollection(content: string, nearIndex: number): string[] {
  // Look at 2000 chars around the telemetry code for data patterns
  const contextStart = Math.max(0, nearIndex - 1000);
  const contextEnd = Math.min(content.length, nearIndex + 1000);
  const context = content.slice(contextStart, contextEnd);

  const collected: string[] = [];
  for (const { pattern, field } of DATA_COLLECTION_PATTERNS) {
    if (pattern.test(context)) {
      collected.push(field);
    }
  }

  return collected;
}

/**
 * Determine opt-out information for a file.
 */
function determineOptOut(
  content: string,
  manifest: VsixManifest,
  allFileContents: Map<string, string>,
): OptOutInfo {
  // Check VS Code API first (highest priority)
  // Check all files since opt-out might be in a different file than telemetry
  for (const fileContent of allFileContents.values()) {
    if (detectVsCodeApiOptOut(fileContent)) {
      return {
        available: true,
        method: "vscode-api",
        settingName: "vscode.env.isTelemetryEnabled",
      };
    }
  }

  // Check current file for VS Code API
  if (detectVsCodeApiOptOut(content)) {
    return {
      available: true,
      method: "vscode-api",
      settingName: "vscode.env.isTelemetryEnabled",
    };
  }

  // Check manifest for configuration
  const manifestOptOut = detectManifestOptOut(manifest);
  if (manifestOptOut.found) {
    return {
      available: true,
      method: "manifest-config",
      settingName: manifestOptOut.settingName,
    };
  }

  // Check code conditional patterns in all files
  for (const fileContent of allFileContents.values()) {
    const codeOptOut = detectCodeConditionalOptOut(fileContent);
    if (codeOptOut.found) {
      return {
        available: true,
        method: "code-conditional",
        settingName: codeOptOut.settingName,
      };
    }
  }

  // Check current file for code conditional
  const codeOptOut = detectCodeConditionalOptOut(content);
  if (codeOptOut.found) {
    return {
      available: true,
      method: "code-conditional",
      settingName: codeOptOut.settingName,
    };
  }

  return { available: false, method: "none", settingName: null };
}

/**
 * Analyze a file for telemetry usage.
 */
function analyzeFile(
  filename: string,
  content: string,
  manifest: VsixManifest,
  telemetryServices: Map<string, TelemetryServiceInfo>,
  allFileContents: Map<string, string>,
  seenServices: Set<string>,
): TelemetryDetection[] {
  const detections: TelemetryDetection[] = [];

  // Detect SDK imports
  const sdkImports = detectSdkImports(content);
  for (const { pkg, info, index } of sdkImports) {
    const serviceKey = `${info.name}:sdk`;
    if (seenServices.has(serviceKey)) continue;
    seenServices.add(serviceKey);

    const line = findLineNumberByString(content, pkg);
    const dataCollected = detectDataCollection(content, index);
    const optOut = determineOptOut(content, manifest, allFileContents);

    detections.push({
      serviceName: info.name,
      serviceCategory: info.category,
      endpoint: null,
      sdkPackage: pkg,
      isKnownService: true,
      dataCollected,
      optOut,
      file: filename,
      line,
    });
  }

  // Detect telemetry endpoints
  const urls = extractUrls(content);
  for (const { url, index } of urls) {
    const domain = extractDomain(url);
    if (!domain) continue;

    // Skip documentation URLs for known services
    // (e.g., https://posthog.com/docs/... is not a telemetry endpoint)
    if (isDocumentationUrl(url)) continue;

    // Check against known telemetry services
    const serviceInfo = telemetryServices.get(domain);
    if (serviceInfo) {
      // Only flag one endpoint per service per file
      const serviceKey = `${serviceInfo.name}:endpoint`;
      if (seenServices.has(serviceKey)) continue;
      seenServices.add(serviceKey);

      const line = findLineNumberByString(content, url);
      const dataCollected = detectDataCollection(content, index);
      const optOut = determineOptOut(content, manifest, allFileContents);

      detections.push({
        serviceName: serviceInfo.name,
        serviceCategory: serviceInfo.category,
        endpoint: url,
        sdkPackage: null,
        isKnownService: true,
        dataCollected,
        optOut,
        file: filename,
        line,
      });
    } else if (isTelemetryPath(url)) {
      // Unknown service but telemetry-like URL path
      const serviceKey = `unknown:endpoint:${domain}`;
      if (seenServices.has(serviceKey)) continue;
      seenServices.add(serviceKey);

      const line = findLineNumberByString(content, url);
      const dataCollected = detectDataCollection(content, index);
      const optOut = determineOptOut(content, manifest, allFileContents);

      detections.push({
        serviceName: domain,
        serviceCategory: "analytics",
        endpoint: url,
        sdkPackage: null,
        isKnownService: false,
        dataCollected,
        optOut,
        file: filename,
        line,
      });
    }
  }

  return detections;
}

/**
 * Convert a detection to a finding.
 */
function detectionToFinding(detection: TelemetryDetection): Finding {
  const optOutStatus = detection.optOut.available
    ? `Opt-out available via ${detection.optOut.method}${detection.optOut.settingName ? ` (${detection.optOut.settingName})` : ""}.`
    : "No opt-out mechanism detected.";

  const detectionMethod = detection.sdkPackage
    ? `via SDK import (${detection.sdkPackage})`
    : `via endpoint URL`;

  const description = `Extension sends telemetry to ${detection.serviceName} ${detectionMethod}. ${optOutStatus}`;

  // High severity if no opt-out, medium if opt-out exists
  const severity = detection.optOut.available ? "medium" : "high";

  return {
    id: "TELEMETRY_DETECTED",
    title: `Telemetry detected: ${detection.serviceName}`,
    description,
    severity,
    category: "telemetry",
    location:
      detection.line !== undefined
        ? { file: detection.file, line: detection.line }
        : { file: detection.file },
    metadata: {
      endpoint: detection.endpoint,
      isKnownService: detection.isKnownService,
      serviceName: detection.serviceName,
      sdkPackage: detection.sdkPackage,
      serviceCategory: detection.serviceCategory,
      dataCollected: detection.dataCollected,
      optOut: detection.optOut,
    },
  };
}

/**
 * Main telemetry check function.
 */
export function checkTelemetry(contents: VsixContents, zooData: ZooData): Finding[] {
  const findings: Finding[] = [];

  // Pre-load all file contents for cross-file opt-out detection
  const allFileContents = new Map<string, string>();
  for (const [filename, buffer] of contents.files) {
    if (filename.includes("node_modules/") || filename.includes("vendor/")) continue;
    if (!isScannable(filename, SCANNABLE_EXTENSIONS_PATTERN)) continue;

    const ext = filename.slice(filename.lastIndexOf(".")).toLowerCase();
    if (![".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"].includes(ext)) continue;

    allFileContents.set(filename, buffer.toString("utf8"));
  }

  // Track services seen across all files to avoid duplicate findings
  const seenServices = new Set<string>();

  for (const [filename, content] of allFileContents) {
    const detections = analyzeFile(
      filename,
      content,
      contents.manifest,
      zooData.telemetryServices,
      allFileContents,
      seenServices,
    );

    for (const detection of detections) {
      findings.push(detectionToFinding(detection));
    }
  }

  return findings;
}
