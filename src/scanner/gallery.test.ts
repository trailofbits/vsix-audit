import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { queryCursor, queryExtension } from "#internal/scanner/download.js";

const versions = [
  { version: "3.0.34", lastUpdated: "2026-10-30T00:00:00Z", files: [] },
  { version: "3.0.25", lastUpdated: "2026-01-01T00:00:00Z", files: [] },
];
const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (_input, init): Promise<Response> => {
    if (typeof init?.body !== "string") throw new Error("Gallery query must have a JSON body");
    const { flags } = JSON.parse(init.body) as { flags: number };
    return Response.json({
      results: [
        {
          extensions: [
            {
              publisher: { publisherName: "dbaeumer" },
              extensionName: "vscode-eslint",
              versions:
                (flags & 0x1) === 0 ? [] : (flags & 0x200) !== 0 ? versions.slice(0, 1) : versions,
              statistics: (flags & 0x100) !== 0 ? [{ statisticName: "install", value: 42 }] : [],
            },
          ],
        },
      ],
    });
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => vi.unstubAllGlobals());

describe.each([
  {
    name: "Marketplace",
    query: queryExtension,
    registry: "marketplace",
    url: "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
  },
  {
    name: "Cursor",
    query: queryCursor,
    registry: "cursor",
    url: "https://marketplace.cursorapi.com/_apis/public/gallery/extensionquery",
  },
])("$name version selection", ({ query, registry, url }) => {
  it("retrieves a pinned older version and install statistics", async () => {
    const result = await query("dbaeumer", "vscode-eslint", "3.0.25");
    expect(result).toMatchObject({ version: "3.0.25", registry, installCount: 42 });
    expect(fetchMock.mock.calls[0]?.[0]).toBe(url);
  });

  it.each([undefined, ""])("keeps the latest-only query for version %j", async (version) => {
    const result = await query("dbaeumer", "vscode-eslint", version);
    expect(result).toMatchObject({ version: "3.0.34", installCount: 42 });
    const body = fetchMock.mock.calls[0]?.[1]?.body;
    if (typeof body !== "string") throw new Error("Expected a gallery JSON request body");
    const request = JSON.parse(body) as { flags: number };
    expect(request.flags & 0x200).toBe(0x200);
  });

  it("reports a missing pin without substituting the latest version", async () => {
    await expect(query("dbaeumer", "vscode-eslint", "0.0.0")).rejects.toThrow(
      "Version 0.0.0 not found for dbaeumer.vscode-eslint. Latest: 3.0.34",
    );
  });

  it("reports an extension with no versions", async () => {
    fetchMock.mockResolvedValueOnce(
      Response.json({
        results: [
          {
            extensions: [
              {
                publisher: { publisherName: "dbaeumer" },
                extensionName: "vscode-eslint",
                versions: [],
              },
            ],
          },
        ],
      }),
    );
    await expect(query("dbaeumer", "vscode-eslint")).rejects.toThrow(
      "No versions available for dbaeumer.vscode-eslint",
    );
  });

  it("reports omitted version data without a property access error", async () => {
    fetchMock.mockResolvedValueOnce(
      Response.json({
        results: [
          {
            extensions: [
              {
                publisher: { publisherName: "dbaeumer" },
                extensionName: "vscode-eslint",
              },
            ],
          },
        ],
      }),
    );
    await expect(query("dbaeumer", "vscode-eslint")).rejects.toThrow(
      "No versions available for dbaeumer.vscode-eslint",
    );
  });

  it("reports registry failures", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 503 }));
    await expect(query("dbaeumer", "vscode-eslint", "3.0.25")).rejects.toThrow("API error: 503");
  });
});
