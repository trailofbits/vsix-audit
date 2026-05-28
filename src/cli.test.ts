import { describe, expect, it } from "vitest";
import { isExtensionId } from "./cli.js";

describe("isExtensionId", () => {
  it("accepts dot-form extension IDs", () => {
    expect(isExtensionId("ms-python.python")).toBe(true);
    expect(isExtensionId("ms-python.python@2024.1.0")).toBe(true);
  });

  it("accepts slash-form extension IDs", () => {
    expect(isExtensionId("ms-python/python")).toBe(true);
    expect(isExtensionId("ms-python/python@2024.1.0")).toBe(true);
    expect(isExtensionId("openvsx:redhat/java")).toBe(true);
  });

  it("keeps explicit and existing relative paths as paths", () => {
    expect(isExtensionId("./ms-python/python")).toBe(false);
    expect(isExtensionId("/tmp/ms-python/python")).toBe(false);
    expect(isExtensionId("missing/ms-python.vsix")).toBe(false);
    expect(isExtensionId("src/cli.ts")).toBe(false);
  });

  it("rejects malformed slash-form extension IDs", () => {
    expect(isExtensionId("ms-python/python/extra")).toBe(false);
    expect(isExtensionId("ms-python/")).toBe(false);
  });
});
