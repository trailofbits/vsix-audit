import { isScannable, JS_EXTENSIONS } from "#internal/scanner/constants.js";
import type {
  Finding,
  TelemetryCategory,
  TelemetryServiceInfo,
  VsixContents,
  VsixManifest,
  ZooData,
} from "#internal/scanner/types.js";
import {
  computeLineStarts,
  findLineNumberByString,
  getStringContent,
} from "#internal/scanner/utils.js";

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

interface TelemetryDetection {
  serviceName: string;
  serviceCategory: TelemetryCategory;
  endpoint: string | null;
  sdkPackage: string | null;
  isKnownService: boolean;
  dataCollected: string[];
  optOutReferences: string[];
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
    results.push({ url: match[0], index: match.index });
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
    if (pkg !== undefined && pkg !== "" && TELEMETRY_SDKS[pkg]) {
      const info = TELEMETRY_SDKS[pkg];
      results.push({ pkg, info, index: match.index });
    }
  }

  // CommonJS: require("package")
  const cjsPattern = /require\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const match of content.matchAll(cjsPattern)) {
    const pkg = match[1];
    if (pkg !== undefined && pkg !== "" && TELEMETRY_SDKS[pkg]) {
      const info = TELEMETRY_SDKS[pkg];
      results.push({ pkg, info, index: match.index });
    }
  }

  return results;
}

function manifestTelemetrySettings(manifest: VsixManifest): string[] {
  const configuration = manifest.contributes?.["configuration"];
  const configurations: unknown[] = Array.isArray(configuration) ? configuration : [configuration];
  const settings: string[] = [];
  for (const item of configurations) {
    if (typeof item !== "object" || item === null || !("properties" in item)) continue;
    const properties = item.properties;
    if (typeof properties !== "object" || properties === null) continue;
    settings.push(
      ...Object.keys(properties).filter((key) => /telemetry|analytics|tracking/i.test(key)),
    );
  }
  return settings;
}

function collectOptOutReferences(manifest: VsixManifest, files: Map<string, string>): string[] {
  const references = new Set(manifestTelemetrySettings(manifest));
  for (const content of files.values()) {
    if (/\bisTelemetryEnabled\b/.test(content)) references.add("isTelemetryEnabled");
    const settings = /(?:get|config\.get)\s*\(\s*["']([^"']*telemetry[^"']*)["']/gi;
    for (const match of content.matchAll(settings)) {
      if (match[1] !== undefined) references.add(match[1]);
    }
  }
  return [...references];
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

interface EndpointService {
  name: string;
  category: TelemetryCategory;
  key: string;
  known: boolean;
}

function endpointService(
  url: string,
  services: Map<string, TelemetryServiceInfo>,
): EndpointService | undefined {
  const domain = extractDomain(url);
  if (domain === null || domain === "" || isDocumentationUrl(url)) return undefined;
  const info = services.get(domain);
  if (info !== undefined) {
    return { name: info.name, category: info.category, key: `${info.name}:endpoint`, known: true };
  }
  if (!isTelemetryPath(url)) return undefined;
  return { name: domain, category: "analytics", key: `unknown:endpoint:${domain}`, known: false };
}

/**
 * Analyze a file for telemetry usage.
 */
function analyzeFile(
  filename: string,
  content: string,
  context: {
    telemetryServices: Map<string, TelemetryServiceInfo>;
    optOutReferences: string[];
    seenServices: Set<string>;
  },
): TelemetryDetection[] {
  const { telemetryServices, optOutReferences, seenServices } = context;
  const detections: TelemetryDetection[] = [];
  const lineStarts = computeLineStarts(content);

  // Detect SDK imports
  const sdkImports = detectSdkImports(content);
  for (const { pkg, info, index } of sdkImports) {
    const serviceKey = `${info.name}:sdk`;
    if (seenServices.has(serviceKey)) continue;
    seenServices.add(serviceKey);

    const line = findLineNumberByString(content, pkg, lineStarts);
    const dataCollected = detectDataCollection(content, index);

    detections.push({
      serviceName: info.name,
      serviceCategory: info.category,
      endpoint: null,
      sdkPackage: pkg,
      isKnownService: true,
      dataCollected,
      optOutReferences,
      file: filename,
      line,
    });
  }

  for (const { url, index } of extractUrls(content)) {
    const service = endpointService(url, telemetryServices);
    if (service === undefined || seenServices.has(service.key)) continue;
    seenServices.add(service.key);
    detections.push({
      serviceName: service.name,
      serviceCategory: service.category,
      endpoint: url,
      sdkPackage: null,
      isKnownService: service.known,
      dataCollected: detectDataCollection(content, index),
      optOutReferences,
      file: filename,
      line: findLineNumberByString(content, url, lineStarts),
    });
  }

  return detections;
}

/**
 * Convert a detection to a finding.
 */
function detectionToFinding(detection: TelemetryDetection): Finding {
  const detectionMethod =
    detection.sdkPackage !== null && detection.sdkPackage !== ""
      ? `via SDK import (${detection.sdkPackage})`
      : `via endpoint URL`;

  const description =
    `Extension references telemetry service ${detection.serviceName} ${detectionMethod}. ` +
    "Opt-out enforcement has not been verified.";

  return {
    id: "TELEMETRY_DETECTED",
    title: `Telemetry detected: ${detection.serviceName}`,
    description,
    severity: "high",
    category: "telemetry",
    capabilities: ["network"],
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
      optOut: { enforcement: "unverified", references: detection.optOutReferences },
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
    if (!isScannable(filename, JS_EXTENSIONS)) continue;

    allFileContents.set(filename, getStringContent(contents, filename, buffer));
  }

  // Track services seen across all files to avoid duplicate findings
  const context = {
    telemetryServices: zooData.telemetryServices,
    optOutReferences: collectOptOutReferences(contents.manifest, allFileContents),
    seenServices: new Set<string>(),
  };

  for (const [filename, content] of allFileContents) {
    const detections = analyzeFile(filename, content, context);

    for (const detection of detections) {
      findings.push(detectionToFinding(detection));
    }
  }

  return findings;
}
