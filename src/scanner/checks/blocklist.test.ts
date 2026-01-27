import { describe, expect, it } from "vitest";
import type { BlocklistEntry, VsixManifest } from "../types.js";
import { checkBlocklist } from "./blocklist.js";

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
});
