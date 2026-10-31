import { describe, expect, it } from "vitest";
import { parseManifest } from "#internal/scanner/manifest.js";

const identity = { name: "fixture", version: "1.0.0" };

describe("parseManifest", () => {
  it("preserves unrelated fields without interpreting them as results", () => {
    const manifest = { ...identity, id: "custom-id", dependencies: { debug: "4.4.2" } };
    expect(parseManifest(Buffer.from(JSON.stringify(manifest)), "/fixture/package.json")).toEqual(
      manifest,
    );
  });

  it("retains research samples that do not declare a publisher", () => {
    expect(parseManifest(Buffer.from(JSON.stringify(identity)), "/sample/package.json")).toEqual(
      identity,
    );
  });

  it.each([
    null,
    [],
    { version: "1.0.0" },
    { name: "fixture" },
    { ...identity, name: "" },
    { ...identity, publisher: 42 },
    { ...identity, main: [] },
    { ...identity, activationEvents: "*" },
    { ...identity, extensionDependencies: [42] },
    { ...identity, dependencies: [] },
    { ...identity, scripts: { postinstall: 42 } },
    { ...identity, contributes: [] },
    { ...identity, contributes: { themes: {} } },
    { ...identity, contributes: { themes: [null] } },
    { ...identity, contributes: { iconThemes: [{ path: 42 }] } },
  ])("rejects malformed consumed fields in %j", (value) => {
    expect(() =>
      parseManifest(Buffer.from(JSON.stringify(value)), "/fixture/package.json"),
    ).toThrow(/\/fixture\/package.json.*must be.*Repair package.json/);
  });

  it("names the invalid JSON input and preserves its cause", () => {
    expect(() => parseManifest(Buffer.from("{"), "/fixture/package.json")).toThrow(
      "Cannot parse /fixture/package.json: repair package.json JSON.",
    );
  });
});
