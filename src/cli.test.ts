import { describe, expect, it } from "vitest";
import { classifyTarget } from "./cli.js";

describe("classifyTarget", () => {
  const missing = () => false;
  const existing = () => true;

  it("classifies dot-form extension IDs", () => {
    expect(classifyTarget("ms-python.python", { exists: missing })).toMatchObject({
      kind: "extension-id",
      extensionId: "ms-python.python",
      unprefixedExtensionId: "ms-python/python",
      parsed: { publisher: "ms-python", name: "python", registry: "marketplace" },
    });
    expect(classifyTarget("ms-python.python@2024.1.0", { exists: missing })).toMatchObject({
      kind: "extension-id",
      unprefixedExtensionId: "ms-python/python@2024.1.0",
      parsed: { version: "2024.1.0" },
    });
  });

  it("classifies slash-form extension IDs", () => {
    expect(classifyTarget("ms-python/python", { exists: missing })).toMatchObject({
      kind: "extension-id",
      extensionId: "ms-python/python",
      unprefixedExtensionId: "ms-python/python",
    });
    expect(classifyTarget("ms-python/python@2024.1.0", { exists: missing })).toMatchObject({
      kind: "extension-id",
      unprefixedExtensionId: "ms-python/python@2024.1.0",
    });
    expect(classifyTarget("openvsx:redhat/java", { exists: existing })).toMatchObject({
      kind: "extension-id",
      extensionId: "openvsx:redhat/java",
      unprefixedExtensionId: "redhat/java",
      parsed: { publisher: "redhat", name: "java", registry: "openvsx" },
    });
  });

  it("classifies explicit and existing relative paths as paths", () => {
    expect(classifyTarget("./ms-python/python", { exists: missing })).toEqual({
      kind: "path",
      path: "./ms-python/python",
    });
    expect(classifyTarget("../ms-python/python", { exists: missing })).toEqual({
      kind: "path",
      path: "../ms-python/python",
    });
    expect(classifyTarget("/tmp/ms-python/python", { exists: missing })).toEqual({
      kind: "path",
      path: "/tmp/ms-python/python",
    });
    expect(classifyTarget("C:\\tmp\\extension", { exists: missing })).toEqual({
      kind: "path",
      path: "C:\\tmp\\extension",
    });
    expect(classifyTarget("src/cli.ts", { exists: existing })).toEqual({
      kind: "path",
      path: "src/cli.ts",
    });
  });

  it("keeps explicit relative VSIX paths as paths even when missing", () => {
    expect(classifyTarget("missing/ms-python.vsix", { exists: missing })).toEqual({
      kind: "path",
      path: "missing/ms-python.vsix",
    });
  });

  it("classifies malformed slash-form extension IDs as paths", () => {
    expect(classifyTarget("ms-python/python/extra", { exists: missing })).toEqual({
      kind: "path",
      path: "ms-python/python/extra",
    });
    expect(classifyTarget("ms-python/", { exists: missing })).toEqual({
      kind: "path",
      path: "ms-python/",
    });
  });
});
