import type { Finding, VsixManifest } from "../types.js";

export function checkActivationEvents(manifest: VsixManifest): Finding[] {
  const findings: Finding[] = [];

  if (manifest.activationEvents?.includes("*")) {
    findings.push({
      id: "ACTIVATION_WILDCARD",
      title: "Extension activates on all events",
      description:
        'Extension uses "activationEvents": ["*"] which activates on every VS Code action. This is often used by malware to ensure immediate execution, but may be legitimate for extensions that need to respond to many different events.',
      severity: "high",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        legitimateUses: ["Extensions with many contribution points", "Global workspace tools"],
        redFlags: ["Simple extension with wildcard activation", "Combined with suspicious patterns"],
      },
    });
  }

  if (manifest.activationEvents?.includes("onStartupFinished")) {
    findings.push({
      id: "ACTIVATION_STARTUP",
      title: "Extension activates on startup",
      description:
        'Extension uses "onStartupFinished" activation event. Common in extensions that need to initialize early (git integration, status bar items, language servers). Review if early activation is necessary for the extension\'s purpose.',
      severity: "medium",
      category: "manifest",
      location: {
        file: "package.json",
      },
      metadata: {
        legitimateUses: ["Git integration", "Status bar extensions", "Language servers", "Background services"],
        redFlags: ["Combined with network activity on startup", "No obvious need for early activation"],
      },
    });
  }

  return findings;
}

export function checkThemeAbuse(manifest: VsixManifest): Finding[] {
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
        "This extension contributes themes/icon themes but also has a code entry point (main/browser). Pure themes don't need executable code. However, some legitimate extensions combine themes with additional functionality (commands, settings sync).",
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
        legitimateUses: ["Theme packs with additional commands", "Theme switchers", "Theme previews"],
        redFlags: ["Theme-only description but runs code", "Network activity from theme extension", "Known malware pattern"],
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
          description: `Extension depends on "${dep}" which provides remote system access. This is expected for extensions that enhance remote development workflows.`,
          severity: "medium",
          category: "manifest",
          location: {
            file: "package.json",
          },
          metadata: {
            dependency: dep,
            legitimateUses: ["Remote development helpers", "SSH workflow tools", "Container development"],
            redFlags: ["No clear remote development purpose", "Combined with credential access patterns"],
          },
        });
      }
    }
  }

  return findings;
}

export function checkManifest(manifest: VsixManifest): Finding[] {
  return [
    ...checkActivationEvents(manifest),
    ...checkThemeAbuse(manifest),
    ...checkSuspiciousPermissions(manifest),
  ];
}
