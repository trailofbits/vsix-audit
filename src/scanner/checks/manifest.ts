import type { Finding, VsixContents, VsixManifest } from "../types.js";

export function checkActivationEvents(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];

  if (manifest.activationEvents?.includes("*")) {
    findings.push({
      id: "ACTIVATION_WILDCARD",
      title: "Extension activates on all events",
      description:
        'Extension uses "activationEvents": ["*"] which activates on every VS Code action. This is often used by malware to ensure immediate execution.',
      severity: "high",
      category: "manifest",
      location: {
        file: "package.json",
      },
    });
  }

  if (manifest.activationEvents?.includes("onStartupFinished")) {
    findings.push({
      id: "ACTIVATION_STARTUP",
      title: "Extension activates on startup",
      description:
        'Extension uses "onStartupFinished" activation event. While legitimate for some extensions, this is commonly used by malware for persistence.',
      severity: "medium",
      category: "manifest",
      location: {
        file: "package.json",
      },
    });
  }

  return findings;
}

export function checkThemeAbuse(manifest: VsixManifest, _contents: VsixContents): Finding[] {
  const findings: Finding[] = [];
  const hasMain = Boolean(manifest.main || manifest.browser);
  const hasThemes =
    (manifest.contributes?.themes?.length ?? 0) > 0 ||
    (manifest.contributes?.iconThemes?.length ?? 0) > 0;

  if (hasThemes && hasMain) {
    findings.push({
      id: "THEME_WITH_CODE",
      title: "Theme extension has code entry point",
      description:
        "This extension contributes themes/icon themes but also has a code entry point (main/browser). Legitimate themes don't need executable code. This pattern is used by malware disguised as themes.",
      severity: "high",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        main: manifest.main,
        browser: manifest.browser,
        themes: manifest.contributes?.themes?.length ?? 0,
        iconThemes: manifest.contributes?.iconThemes?.length ?? 0,
      },
    });
  }

  return findings;
}

export function checkSuspiciousPermissions(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];

  const extensionDependencies = manifest["extensionDependencies"] as string[] | undefined;
  if (extensionDependencies) {
    for (const dep of extensionDependencies) {
      if (dep.includes("remote-ssh") || dep.includes("remote-wsl")) {
        findings.push({
          id: "REMOTE_DEPENDENCY",
          title: "Extension depends on remote access extension",
          description: `Extension depends on "${dep}" which provides remote system access. This could indicate intent to access remote systems.`,
          severity: "medium",
          category: "manifest",
          location: {
            file: "package.json",
          },
          metadata: {
            dependency: dep,
          },
        });
      }
    }
  }

  return findings;
}

export function checkManifest(manifest: VsixManifest, contents: VsixContents): Finding[] {
  return [
    ...checkActivationEvents(manifest),
    ...checkThemeAbuse(manifest, contents),
    ...checkSuspiciousPermissions(manifest),
  ];
}
