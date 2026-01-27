import { describe, expect, it } from "vitest";
import type { VsixManifest } from "../types.js";
import { checkActivationEvents, checkManifest, checkThemeAbuse } from "./manifest.js";

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

describe("checkManifest", () => {
  it("combines all manifest checks", () => {
    const manifest: VsixManifest = {
      name: "suspicious-theme",
      publisher: "suspicious",
      version: "1.0.0",
      main: "./extension.js",
      activationEvents: ["*"],
      contributes: {
        themes: [{ id: "theme", label: "Theme", path: "./theme.json" }],
      },
    };

    const findings = checkManifest(manifest);
    expect(findings.some((f) => f.id === "ACTIVATION_WILDCARD")).toBe(true);
    expect(findings.some((f) => f.id === "THEME_WITH_CODE")).toBe(true);
  });
});
