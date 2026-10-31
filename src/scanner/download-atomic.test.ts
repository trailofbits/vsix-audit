import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { downloadVsix } from "#internal/scanner/download.js";

let root: string;
let destination: string;
const fetchMock = vi.fn<typeof fetch>();

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-audit-atomic-"));
  destination = join(root, "extension.vsix");
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await rm(root, { recursive: true, force: true });
});

it("replaces an existing VSIX after a successful download", async () => {
  await writeFile(destination, "existing complete VSIX");
  fetchMock.mockResolvedValue(new Response("fresh complete VSIX"));

  await downloadVsix("test", "extension", "1.0.0", destination, "openvsx");

  expect(await readFile(destination, "utf8")).toBe("fresh complete VSIX");
  expect(await readdir(root)).toEqual(["extension.vsix"]);
});

it.each([false, true])(
  "leaves the destination unchanged after a stream failure with existing file=%s",
  async (existing) => {
    if (existing) await writeFile(destination, "existing complete VSIX");
    fetchMock.mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller): void {
            controller.enqueue(new Uint8Array([1, 2, 3]));
            setTimeout(() => {
              controller.error(new Error("Download interrupted"));
            }, 20);
          },
        }),
      ),
    );

    await expect(
      downloadVsix("test", "extension", "1.0.0", destination, "openvsx"),
    ).rejects.toThrow("Download interrupted");

    const saved = await readFile(destination, "utf8").catch((error: unknown) => {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
      throw error;
    });
    expect(saved).toBe(existing ? "existing complete VSIX" : undefined);
    expect(await readdir(root)).toEqual(existing ? ["extension.vsix"] : []);
  },
);

it.each([
  {
    name: "HTTP error",
    response: (): Response => new Response(null, { status: 503 }),
    error: /503/,
  },
  {
    name: "missing response body",
    response: (): Response => new Response(null),
    error: /Empty response/,
  },
  {
    name: "oversized response",
    response: (): Response => new Response("", { headers: { "content-length": "524288001" } }),
    error: /Download too large/,
  },
])("preserves an existing VSIX after $name", async ({ response, error }) => {
  await writeFile(destination, "existing complete VSIX");
  fetchMock.mockResolvedValue(response());

  await expect(downloadVsix("test", "extension", "1.0.0", destination, "openvsx")).rejects.toThrow(
    error,
  );

  expect(await readFile(destination, "utf8")).toBe("existing complete VSIX");
  expect(await readdir(root)).toEqual(["extension.vsix"]);
});

it("keeps an existing directory intact when the destination cannot be replaced", async () => {
  await mkdir(destination);
  await writeFile(join(destination, "keep.txt"), "keep this file");
  fetchMock.mockResolvedValue(new Response("fresh VSIX"));

  await expect(downloadVsix("test", "extension", "1.0.0", destination, "openvsx")).rejects.toThrow(
    destination,
  );

  expect(await readFile(join(destination, "keep.txt"), "utf8")).toBe("keep this file");
  expect(await readdir(root)).toEqual(["extension.vsix"]);
});
