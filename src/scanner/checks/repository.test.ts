import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRepositoryCheck } from "#internal/scanner/checks/repository.js";
import type { VsixContents } from "#internal/scanner/types.js";

const fetchMock = vi.fn<typeof fetch>();
function contents(repository?: unknown, xml?: string): VsixContents {
  return {
    manifest: { name: "fixture", version: "1.0.0", repository },
    files:
      xml === undefined
        ? new Map<string, Buffer>()
        : new Map([["extension.vsixmanifest", Buffer.from(xml)]]),
    basePath: "/fixture",
  };
}

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (): Promise<Response> =>
    Response.json([{ sha: "a".repeat(40) }]),
  );
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("GITHUB_TOKEN", "");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("repository observations", () => {
  it("reports absent source links at low severity without making a request", async () => {
    expect(await createRepositoryCheck()(contents())).toMatchObject({
      findings: [{ id: "REPOSITORY_LINK_MISSING", severity: "low" }],
      warnings: [],
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("accepts a repository that contains commits with a single API request", async () => {
    expect(
      await createRepositoryCheck()(contents({ url: "git+https://github.com/example/source.git" })),
    ).toEqual({ findings: [], warnings: [] });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toEqual(
      new URL("https://api.github.com/repos/example/source/commits?per_page=1"),
    );
  });

  it.each([
    (): Response => Response.json([]),
    (): Response => Response.json({ message: "Git Repository is empty." }, { status: 409 }),
  ])("reports confirmed empty repositories", async (response) => {
    fetchMock.mockResolvedValue(response());
    expect(await createRepositoryCheck()(contents("example/source"))).toMatchObject({
      findings: [
        {
          id: "REPOSITORY_EMPTY",
          severity: "low",
          metadata: {
            repo: "https://github.com/example/source",
            field: "repository",
          },
        },
      ],
      warnings: [],
    });
  });

  it("reports private or missing repositories as inaccessible", async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(Response.json({ login: "example" }));
    const result = await createRepositoryCheck()(contents("example/private"));
    expect(result).toMatchObject({
      findings: [{ id: "REPOSITORY_UNAVAILABLE", severity: "low" }],
      warnings: [],
    });
    expect(result.findings[0]?.description).toContain("missing or private");
    expect(fetchMock.mock.calls[1]?.[0]).toEqual(new URL("https://api.github.com/users/example"));
  });

  it("identifies inaccessible owners separately", async () => {
    fetchMock.mockImplementation(async (): Promise<Response> => Response.json({}, { status: 404 }));
    expect(await createRepositoryCheck()(contents("example/source"))).toMatchObject({
      findings: [{ id: "REPOSITORY_OWNER_UNAVAILABLE", severity: "low" }],
      warnings: [],
    });
  });
});

describe("unverified repositories", () => {
  it.each([
    (): Response => Response.json({ message: "Repository unavailable" }, { status: 409 }),
    (): Response => new Response(null, { status: 429 }),
    (): Response => new Response(null, { status: 503 }),
    (): Response => Response.json({ unexpected: true }),
    (): Response => Response.json([{ sha: "" }]),
  ])("keeps API failures and unknown data out of malware findings", async (response) => {
    fetchMock.mockResolvedValue(response());
    const result = await createRepositoryCheck()(contents("example/source"));
    expect(result.findings).toEqual([]);
    expect(result.warnings).toHaveLength(1);
  });

  it.each([
    (): Response => new Response(null, { status: 503 }),
    (): Response => Response.json({ unexpected: true }),
  ])("retains repository evidence when the owner cannot be verified", async (owner) => {
    fetchMock
      .mockResolvedValueOnce(Response.json({}, { status: 404 }))
      .mockResolvedValueOnce(owner());
    const result = await createRepositoryCheck()(contents("example/source"));
    expect(result.findings[0]?.id).toBe("REPOSITORY_UNAVAILABLE");
    expect(result.warnings).toHaveLength(1);
  });

  it.each([
    "https://gitlab.com/example/source",
    "https://github.com:123/example/source",
    "https://user:example-token@github.com/example/source",
    { url: false },
  ])("leaves unsupported or malformed repository %j unverified", async (repository) => {
    const result = await createRepositoryCheck()(contents(repository));
    expect(result.findings).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain("example-token");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("multiple metadata sources", () => {
  const sourceId = "Microsoft.VisualStudio.Services.Links.Source";
  const xml = `<PackageManifest><Metadata><Properties>
    <Property Id="${sourceId}" Value="https://github.com/example/source"/>
    </Properties></Metadata></PackageManifest>`;

  it("deduplicates the package and VSIX declarations", async () => {
    const check = createRepositoryCheck();
    await check(contents("github:example/source", xml));
    await check(contents("example/source"));
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("checks distinct declarations and attributes findings to their metadata", async () => {
    fetchMock
      .mockResolvedValueOnce(Response.json([{ sha: "a".repeat(40) }]))
      .mockResolvedValueOnce(Response.json([]));
    expect(await createRepositoryCheck()(contents("example/other", xml))).toMatchObject({
      findings: [
        {
          id: "REPOSITORY_EMPTY",
          location: { file: "extension.vsixmanifest" },
          metadata: { field: sourceId, repo: "https://github.com/example/source" },
        },
      ],
      warnings: [],
    });
  });

  it("rejects partial links from malformed XML", async () => {
    const result = await createRepositoryCheck()(contents(undefined, xml.slice(0, -5)));
    expect(result.findings).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
