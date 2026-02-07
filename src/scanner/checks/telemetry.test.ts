import { describe, expect, it } from "vitest";
import type { TelemetryServiceInfo, VsixContents, VsixManifest, ZooData } from "../types.js";
import { checkTelemetry } from "./telemetry.js";

function makeContents(
  files: Record<string, string>,
  manifestOverrides?: Partial<VsixManifest>,
): VsixContents {
  const manifest: VsixManifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
    ...manifestOverrides,
  };

  const fileMap = new Map<string, Buffer>();
  for (const [name, content] of Object.entries(files)) {
    fileMap.set(name, Buffer.from(content, "utf8"));
  }

  return { manifest, files: fileMap, basePath: "/test" };
}

function makeZooData(telemetryServices?: Map<string, TelemetryServiceInfo>): ZooData {
  return {
    blocklist: [],
    hashes: new Set(),
    domains: new Set(),
    ips: new Set(),
    maliciousNpmPackages: new Set(),
    wallets: new Set(),
    blockchainAllowlist: new Set(),
    githubC2Accounts: new Set(),
    telemetryServices:
      telemetryServices ??
      new Map([
        ["sentry.io", { name: "Sentry", category: "crash-reporting", domains: ["sentry.io"] }],
        [
          "ingest.sentry.io",
          { name: "Sentry", category: "crash-reporting", domains: ["ingest.sentry.io"] },
        ],
        [
          "api.mixpanel.com",
          { name: "Mixpanel", category: "analytics", domains: ["api.mixpanel.com"] },
        ],
        [
          "api.amplitude.com",
          { name: "Amplitude", category: "analytics", domains: ["api.amplitude.com"] },
        ],
        ["api.segment.io", { name: "Segment", category: "analytics", domains: ["api.segment.io"] }],
        [
          "app.posthog.com",
          { name: "PostHog", category: "analytics", domains: ["app.posthog.com"] },
        ],
        [
          "applicationinsights.azure.com",
          {
            name: "Azure Application Insights",
            category: "apm",
            domains: ["applicationinsights.azure.com"],
          },
        ],
        ["datadoghq.com", { name: "Datadog", category: "apm", domains: ["datadoghq.com"] }],
      ]),
  };
}

describe("checkTelemetry", () => {
  // ============================================================================
  // SDK IMPORT DETECTION
  // ============================================================================

  describe("SDK import detection", () => {
    it("detects ESM Sentry import", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "https://example.ingest.sentry.io/123" });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Sentry");
      expect(finding?.metadata?.["sdkPackage"]).toBe("@sentry/node");
      expect(finding?.metadata?.["serviceCategory"]).toBe("crash-reporting");
    });

    it("detects CommonJS Sentry require", () => {
      const content = `
        const Sentry = require("@sentry/node");
        Sentry.init({ dsn: "https://example.ingest.sentry.io/123" });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Sentry");
      expect(finding?.metadata?.["sdkPackage"]).toBe("@sentry/node");
    });

    it("detects Mixpanel SDK import", () => {
      const content = `
        import Mixpanel from "mixpanel";
        const mixpanel = Mixpanel.init("token");
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Mixpanel");
      expect(finding?.metadata?.["serviceCategory"]).toBe("analytics");
    });

    it("detects VS Code Telemetry SDK", () => {
      const content = `
        import TelemetryReporter from "@vscode/extension-telemetry";
        const reporter = new TelemetryReporter(key);
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("VS Code Telemetry");
      expect(finding?.metadata?.["sdkPackage"]).toBe("@vscode/extension-telemetry");
    });

    it("detects ApplicationInsights SDK", () => {
      const content = `
        const appInsights = require("applicationinsights");
        appInsights.setup("key").start();
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Azure Application Insights");
      expect(finding?.metadata?.["serviceCategory"]).toBe("apm");
    });

    it("detects PostHog SDK", () => {
      const content = `
        import { PostHog } from "posthog-node";
        const client = new PostHog("key");
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("PostHog");
    });
  });

  // ============================================================================
  // ENDPOINT URL DETECTION
  // ============================================================================

  describe("endpoint URL detection", () => {
    it("detects known Sentry endpoint URL", () => {
      const content = `
        const dsn = "https://ingest.sentry.io/api/123/envelope/";
        fetch(dsn, { method: "POST", body: data });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Sentry");
      expect(finding?.metadata?.["endpoint"]).toContain("sentry.io");
      expect(finding?.metadata?.["isKnownService"]).toBe(true);
    });

    it("detects known Mixpanel endpoint URL", () => {
      const content = `
        const url = "https://api.mixpanel.com/track";
        await fetch(url, { body: JSON.stringify(event) });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("Mixpanel");
      expect(finding?.metadata?.["endpoint"]).toContain("mixpanel.com");
    });

    it("detects unknown telemetry URL by path pattern", () => {
      const content = `
        const url = "https://telemetry.example.com/v2/track";
        fetch(url, { body: data });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["serviceName"]).toBe("telemetry.example.com");
      expect(finding?.metadata?.["isKnownService"]).toBe(false);
    });

    it("detects telemetry URL with /api/telemetry path", () => {
      const content = `
        const endpoint = "https://custom.service.io/api/telemetry";
        sendData(endpoint, payload);
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["isKnownService"]).toBe(false);
    });

    it("detects telemetry URL with /collect path", () => {
      const content = `
        navigator.sendBeacon("https://analytics.custom.io/collect", payload);
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
    });
  });

  // ============================================================================
  // OPT-OUT DETECTION
  // ============================================================================

  describe("opt-out detection", () => {
    it("detects VS Code API opt-out (vscode.env.isTelemetryEnabled)", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        import * as vscode from "vscode";

        if (vscode.env.isTelemetryEnabled) {
          Sentry.init({ dsn: "..." });
        }
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["optOut"]).toEqual({
        available: true,
        method: "vscode-api",
        settingName: "vscode.env.isTelemetryEnabled",
      });
      expect(finding?.severity).toBe("medium");
    });

    it("detects manifest configuration opt-out", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents(
        { "extension.ts": content },
        {
          contributes: {
            configuration: {
              properties: {
                "myext.enableTelemetry": {
                  type: "boolean",
                  default: true,
                  description: "Enable telemetry",
                },
              },
            },
          },
        },
      );
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["optOut"]).toEqual({
        available: true,
        method: "manifest-config",
        settingName: "myext.enableTelemetry",
      });
      expect(finding?.severity).toBe("medium");
    });

    it("detects code conditional opt-out via getConfiguration", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        const config = vscode.workspace.getConfiguration("myext");
        if (config.get("enableTelemetry")) {
          Sentry.init({ dsn: "..." });
        }
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["optOut"]).toMatchObject({
        available: true,
        method: "code-conditional",
      });
      expect(finding?.severity).toBe("medium");
    });

    it("sets high severity when no opt-out is detected", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["optOut"]).toEqual({
        available: false,
        method: "none",
        settingName: null,
      });
      expect(finding?.severity).toBe("high");
    });

    it("detects opt-out in a different file (cross-file detection)", () => {
      const telemetryFile = `
        import * as Sentry from "@sentry/node";
        export function init() {
          Sentry.init({ dsn: "..." });
        }
      `;
      const mainFile = `
        import * as vscode from "vscode";
        import { init } from "./telemetry";

        if (vscode.env.isTelemetryEnabled) {
          init();
        }
      `;
      const contents = makeContents({
        "src/telemetry.ts": telemetryFile,
        "src/extension.ts": mainFile,
      });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      expect(finding?.metadata?.["optOut"]).toEqual({
        available: true,
        method: "vscode-api",
        settingName: "vscode.env.isTelemetryEnabled",
      });
    });
  });

  // ============================================================================
  // DATA COLLECTION ANALYSIS
  // ============================================================================

  describe("data collection analysis", () => {
    it("detects common telemetry data fields", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.setTag("extension_version", extensionVersion);
        Sentry.setTag("vscode_version", vscode.version);
        Sentry.setTag("os_platform", process.platform);
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      const dataCollected = finding?.metadata?.["dataCollected"] as string[];
      expect(dataCollected).toContain("extension_version");
      expect(dataCollected).toContain("vscode_version");
      expect(dataCollected).toContain("os_platform");
    });

    it("detects machine_id and session_id collection", () => {
      const content = `
        import analytics from "@segment/analytics-node";
        analytics.track({
          userId: machine_id,
          sessionId: session_id,
          event: "Extension Activated"
        });
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      const dataCollected = finding?.metadata?.["dataCollected"] as string[];
      expect(dataCollected).toContain("machine_id");
      expect(dataCollected).toContain("session_id");
    });

    it("returns empty array when no data fields detected", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");
      const dataCollected = finding?.metadata?.["dataCollected"] as string[];
      expect(dataCollected).toEqual([]);
    });
  });

  // ============================================================================
  // NODE_MODULES EXCLUSIONS
  // ============================================================================

  describe("node_modules exclusions", () => {
    it("skips files in node_modules", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "node_modules/@sentry/node/index.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings).toHaveLength(0);
    });

    it("skips files in vendor directory", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "vendor/telemetry.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings).toHaveLength(0);
    });
  });

  // ============================================================================
  // FILE TYPE FILTERING
  // ============================================================================

  describe("file type filtering", () => {
    it("scans .js files", () => {
      const content = `import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .ts files", () => {
      const content = `import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("scans .mjs files", () => {
      const content = `import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "extension.mjs": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("ignores .json files", () => {
      const content = `{ "import": "@sentry/node" }`;
      const contents = makeContents({ "package.json": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings).toHaveLength(0);
    });

    it("ignores .md files", () => {
      const content = `Use \`import * as Sentry from "@sentry/node"\``;
      const contents = makeContents({ "README.md": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings).toHaveLength(0);
    });
  });

  // ============================================================================
  // EDGE CASES
  // ============================================================================

  describe("edge cases", () => {
    it("handles empty files gracefully", () => {
      const contents = makeContents({ "empty.js": "" });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings).toHaveLength(0);
    });

    it("handles files with no telemetry", () => {
      const content = `
        import * as vscode from "vscode";
        export function activate(context) {
          console.log("Hello");
        }
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      expect(findings).toHaveLength(0);
    });

    it("handles malformed URLs gracefully", () => {
      const content = `
        const url = "not-a-valid-url";
        const url2 = "https://";
        fetch(url);
      `;
      const contents = makeContents({ "extension.js": content });
      const zooData = makeZooData();

      // Should not throw
      const findings = checkTelemetry(contents, zooData);
      expect(Array.isArray(findings)).toBe(true);
    });

    it("deduplicates multiple SDK imports of the same service", () => {
      const content = `
        import { init } from "@sentry/node";
        import * as Sentry from "@sentry/node";
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      // Should only have one finding for Sentry
      const sentryFindings = findings.filter((f) => f.metadata?.["serviceName"] === "Sentry");
      expect(sentryFindings.length).toBe(1);
    });

    it("handles empty zoo data gracefully", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData(new Map());

      // Should still detect SDK imports even without zoo data
      const findings = checkTelemetry(contents, zooData);
      expect(findings.some((f) => f.id === "TELEMETRY_DETECTED")).toBe(true);
    });
  });

  // ============================================================================
  // METADATA AND LOCATION
  // ============================================================================

  describe("metadata and location", () => {
    it("includes line number in location", () => {
      const content = `// line 1
// line 2
import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");

      expect(finding?.location?.line).toBe(3);
    });

    it("includes file path in location", () => {
      const content = `import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "src/telemetry.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");

      expect(finding?.location?.file).toBe("src/telemetry.ts");
    });

    it("assigns telemetry category to all findings", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        import Mixpanel from "mixpanel";
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);

      expect(findings.every((f) => f.category === "telemetry")).toBe(true);
    });
  });

  // ============================================================================
  // SEVERITY DETERMINATION
  // ============================================================================

  describe("severity determination", () => {
    it("returns medium severity with VS Code API opt-out", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        if (vscode.env.isTelemetryEnabled) {
          Sentry.init({ dsn: "..." });
        }
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");

      expect(finding?.severity).toBe("medium");
    });

    it("returns high severity without opt-out", () => {
      const content = `
        import * as Sentry from "@sentry/node";
        Sentry.init({ dsn: "..." });
      `;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");

      expect(finding?.severity).toBe("high");
    });
  });

  // ============================================================================
  // FINDING STRUCTURE
  // ============================================================================

  describe("finding structure", () => {
    it("includes all required metadata fields", () => {
      const content = `import * as Sentry from "@sentry/node";`;
      const contents = makeContents({ "extension.ts": content });
      const zooData = makeZooData();

      const findings = checkTelemetry(contents, zooData);
      const finding = findings.find((f) => f.id === "TELEMETRY_DETECTED");

      expect(finding).toBeDefined();
      expect(finding?.id).toBe("TELEMETRY_DETECTED");
      expect(finding?.title).toContain("Telemetry detected");
      expect(finding?.description).toBeDefined();
      expect(finding?.severity).toBeDefined();
      expect(finding?.category).toBe("telemetry");
      expect(finding?.location).toBeDefined();
      expect(finding?.metadata).toBeDefined();
      expect(finding?.metadata?.["serviceName"]).toBe("Sentry");
      expect(finding?.metadata?.["serviceCategory"]).toBe("crash-reporting");
      expect(finding?.metadata?.["isKnownService"]).toBe(true);
      expect(finding?.metadata?.["optOut"]).toBeDefined();
      expect(finding?.metadata?.["dataCollected"]).toBeDefined();
    });
  });
});
