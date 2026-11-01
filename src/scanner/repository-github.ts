const API_ORIGIN = "https://api.github.com";
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_LOOKUPS = 256;
const MAX_REDIRECTS = 3;
const REQUEST_TIMEOUT_MS = 5_000;

type GitHubError = { error: string; stop?: boolean };
export type GitHubResult = { status: number; data: unknown } | GitHubError;
export type GitHubLookup = (path: string) => Promise<GitHubResult>;

async function cancelResponseBody(response: Response): Promise<void> {
  await response.body?.cancel();
}

function allowedApiUrl(url: URL): boolean {
  return (
    url.origin === API_ORIGIN &&
    url.username === "" &&
    url.password === "" &&
    /^\/(?:repos\/[\w.-]+\/[\w.-]+\/commits|repositories\/\d+\/commits|users\/[\w-]+)$/.test(
      url.pathname,
    )
  );
}

async function readJson(response: Response): Promise<unknown> {
  if (response.body === null) throw new Error("GitHub returned an empty response");
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk: unknown = next.value;
      if (!(chunk instanceof Uint8Array)) throw new Error("GitHub returned non-byte data");
      size += chunk.length;
      if (size > MAX_RESPONSE_BYTES) throw new Error("GitHub response exceeds 256 KiB limit");
      chunks.push(chunk);
    }
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
  const result: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  return result;
}

async function fetchResponse(
  path: string,
  headers: Record<string, string>,
): Promise<Response | GitHubError> {
  let url = new URL(path, API_ORIGIN);
  const signal = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    if (!allowedApiUrl(url)) return { error: "GitHub URL is outside supported API endpoints" };
    const response = await fetch(url, { headers, signal, redirect: "manual" });
    if (response.status >= 300 && response.status < 400) {
      await cancelResponseBody(response);
      const location = response.headers.get("location");
      if (location === null) return { error: "GitHub redirect has no destination" };
      url = new URL(location, url);
      continue;
    }
    return response;
  }
  return { error: "GitHub exceeded 3 redirects; update the repository link" };
}

async function githubRequest(path: string): Promise<GitHubResult> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "vsix-audit",
  };
  const token = process.env["GITHUB_TOKEN"];
  if (token !== undefined && token !== "") headers["Authorization"] = `Bearer ${token}`;
  const response = await fetchResponse(path, headers);
  if ("error" in response) return response;
  if (![200, 404, 409].includes(response.status)) {
    await cancelResponseBody(response);
    return {
      error: `GitHub HTTP ${response.status}; retry later or configure GITHUB_TOKEN`,
      stop:
        [401, 429].includes(response.status) ||
        response.headers.get("x-ratelimit-remaining") === "0" ||
        response.headers.has("retry-after"),
    };
  }
  if (response.status === 404) {
    await cancelResponseBody(response);
    return { status: 404, data: null };
  }
  return { status: response.status, data: await readJson(response) };
}

/** Share serialized GitHub lookups within one scan or batch using a bounded memory cache. */
export function createGitHubLookup(): GitHubLookup {
  const cache = new Map<string, Promise<GitHubResult>>();
  let pending = Promise.resolve();
  let blocked: string | undefined;
  return (path): Promise<GitHubResult> => {
    const cached = cache.get(path);
    if (cached !== undefined) return cached;
    const request = pending.then(async (): Promise<GitHubResult> => {
      if (blocked !== undefined) return { error: blocked };
      try {
        const result = await githubRequest(path);
        if ("error" in result && result.stop === true) blocked = result.error;
        return result;
      } catch {
        return { error: "GitHub request failed or timed out; retry or check network connectivity" };
      }
    });
    pending = request.then((): void => {});
    if (cache.size === MAX_LOOKUPS) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(path, request);
    return request;
  };
}
