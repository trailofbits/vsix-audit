import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createGitHubLookup } from "#internal/scanner/repository-github.js";

const fetchMock = vi.fn<typeof fetch>();
const path = "/repos/example/source/commits?per_page=1";
const commits = [{ sha: "a".repeat(40) }];

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockImplementation(async (): Promise<Response> => Response.json(commits));
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("GITHUB_TOKEN", "");
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("bounded GitHub requests", () => {
  it("uses a fixed API origin, manual redirects, versioned JSON, and a deadline", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    expect(await createGitHubLookup()(path)).toEqual({ status: 200, data: commits });
    expect(fetchMock.mock.calls[0]?.[0]).toEqual(new URL(`https://api.github.com${path}`));
    expect(fetchMock.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      redirect: "manual",
      headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10" },
    });
    expect(timeout).toHaveBeenCalledWith(5000);
  });

  it("supports GITHUB_TOKEN without copying it into errors", async () => {
    vi.stubEnv("GITHUB_TOKEN", "test-token-not-a-credential");
    fetchMock.mockRejectedValue(new Error("test-token-not-a-credential"));
    const result = await createGitHubLookup()(path);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({
      Authorization: "Bearer test-token-not-a-credential",
    });
    expect(JSON.stringify(result)).not.toContain("test-token-not-a-credential");
    expect(result).toHaveProperty("error");
  });

  it.each([401, 403, 429, 500, 503])("reports HTTP %i as unverified", async (status) => {
    fetchMock.mockResolvedValue(new Response(null, { status }));
    expect(await createGitHubLookup()(path)).toHaveProperty(
      "error",
      expect.stringContaining(`${status}`),
    );
  });

  it.each([(): Response => new Response(null), (): Response => new Response("not JSON")])(
    "reports an empty or malformed response",
    async (response) => {
      fetchMock.mockResolvedValue(response());
      expect(await createGitHubLookup()(path)).toHaveProperty("error");
    },
  );

  it("cancels a response that exceeds the byte limit", async () => {
    const cancel = vi.fn<() => void>();
    fetchMock.mockResolvedValue(
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller): void {
            controller.enqueue(new Uint8Array(256 * 1024 + 1));
          },
          cancel,
        }),
      ),
    );
    expect(await createGitHubLookup()(path)).toHaveProperty("error");
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("reports a request that aborts", async () => {
    const controller = new AbortController();
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(controller.signal);
    fetchMock.mockImplementation(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            (): void => {
              reject(new DOMException("Timeout", "TimeoutError"));
            },
            { once: true },
          );
        }),
    );
    const request = createGitHubLookup()(path);
    await vi.waitFor((): void => {
      expect(fetchMock).toHaveBeenCalledOnce();
    });
    controller.abort();
    expect(await request).toHaveProperty("error", expect.stringContaining("timed out"));
  });

  it("rejects response bodies that violate the byte-stream contract", async () => {
    const response = new Response();
    Object.defineProperty(response, "body", {
      value: new ReadableStream<unknown>({
        start(controller): void {
          controller.enqueue("not bytes");
          controller.close();
        },
      }),
    });
    fetchMock.mockResolvedValue(response);
    expect(await createGitHubLookup()(path)).toHaveProperty("error");
  });
});

describe("GitHub redirects and endpoint boundaries", () => {
  it("follows a renamed repository within GitHub's API", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(null, {
        status: 301,
        headers: { location: "https://api.github.com/repositories/123/commits?per_page=1" },
      }),
    );
    expect(await createGitHubLookup()(path)).toEqual({ status: 200, data: commits });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it.each([
    "https://example.invalid/steal",
    "http://api.github.com/repos/example/source/commits",
    "https://user@api.github.com/repos/example/source/commits",
    "https://api.github.com/user",
    "https://api.github.com.evil.test/repos/example/source/commits",
  ])("does not follow unsupported redirect %s", async (location) => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location } }));
    expect(await createGitHubLookup()(path)).toHaveProperty("error");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("reports redirects without a destination", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 301 }));
    expect(await createGitHubLookup()(path)).toHaveProperty(
      "error",
      expect.stringContaining("destination"),
    );
  });

  it("bounds redirect loops", async () => {
    fetchMock.mockImplementation(
      async (): Promise<Response> =>
        new Response(null, {
          status: 301,
          headers: { location: `https://api.github.com${path}` },
        }),
    );
    expect(await createGitHubLookup()(path)).toHaveProperty(
      "error",
      expect.stringContaining("3 redirects"),
    );
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("rejects arbitrary endpoints before making a request", async () => {
    expect(await createGitHubLookup()("https://example.invalid/path")).toHaveProperty("error");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("batch lookup sharing", () => {
  it("shares requests and isolates separate scan sessions", async () => {
    const lookup = createGitHubLookup();
    const first = lookup(path);
    expect(lookup(path)).toBe(first);
    await Promise.all([first, lookup(path), createGitHubLookup()(path)]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("bounds the cache and evicts old lookups", async () => {
    const lookup = createGitHubLookup();
    for (let index = 0; index < 257; index++) {
      await lookup(`/repos/example/source${index}/commits?per_page=1`);
    }
    await lookup("/repos/example/source0/commits?per_page=1");
    expect(fetchMock).toHaveBeenCalledTimes(258);
  });

  it("serializes distinct requests", async () => {
    const release: Array<(response: Response) => void> = [];
    fetchMock.mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          release.push(resolve);
        }),
    );
    const lookup = createGitHubLookup();
    const first = lookup(path);
    const second = lookup("/users/example");
    await vi.waitFor(() => {
      expect(release).toHaveLength(1);
    });
    release[0]?.(Response.json(commits));
    await first;
    await vi.waitFor(() => {
      expect(release).toHaveLength(2);
    });
    release[1]?.(Response.json({ login: "example" }));
    await second;
  });

  it.each([
    { status: 403, headers: { "x-ratelimit-remaining": "0" } },
    { status: 403, headers: { "retry-after": "60" } },
    { status: 429, headers: {} },
    { status: 401, headers: {} },
  ])("stops further requests after rate limits or invalid authentication: %j", async (response) => {
    fetchMock.mockResolvedValue(new Response(null, response));
    const lookup = createGitHubLookup();
    await lookup(path);
    expect(await lookup("/users/example")).toHaveProperty("error");
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
