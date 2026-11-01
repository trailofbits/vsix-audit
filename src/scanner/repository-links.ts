import sax from "sax";
import type { QualifiedTag, Tag } from "sax";
import type { VsixContents } from "#internal/scanner/types.js";

export interface RepositoryLink {
  value: string;
  file: string;
  field: string;
}

export interface GitHubRepository {
  owner: string;
  name: string;
  url: string;
}

interface RepositoryLinks {
  links: RepositoryLink[];
  warnings: string[];
}

const SOURCE_FIELDS = new Set([
  "Microsoft.VisualStudio.Services.Links.Source",
  "Microsoft.VisualStudio.Services.Links.GitHub",
]);
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_LINKS = 8;

function packageRepository(contents: VsixContents): RepositoryLinks {
  const repository = contents.manifest["repository"];
  if (repository === undefined) return { links: [], warnings: [] };
  const value =
    typeof repository === "object" && repository !== null && "url" in repository
      ? repository.url
      : repository;
  if (typeof value !== "string" || value.trim() === "") {
    return {
      links: [],
      warnings: ["Cannot check package.json repository: provide a repository URL or {url} object."],
    };
  }
  return { links: [{ value, file: "package.json", field: "repository" }], warnings: [] };
}

function addVsixProperty(tag: Tag | QualifiedTag, links: RepositoryLink[], file: string): void {
  const id = tag.attributes["Id"];
  if (typeof id !== "string" || !SOURCE_FIELDS.has(id)) return;
  const value = tag.attributes["Value"];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`source property ${id} must contain a URL`);
  }
  if (links.length === MAX_LINKS) throw new Error("VSIX manifest exceeds 8 repository links");
  links.push({ value, file, field: id });
}

function vsixRepositoryLinks(file: string, buffer: Buffer): RepositoryLink[] {
  if (buffer.length > MAX_MANIFEST_BYTES) throw new Error("VSIX manifest exceeds 1 MiB limit");
  const options = { position: false, strictEntities: true };
  const xml = sax.parser(true, options);
  const path: string[] = [];
  const links: RepositoryLink[] = [];
  let root: string | undefined;
  xml.onerror = (error): never => {
    throw error;
  };
  xml.ondoctype = (): never => {
    throw new Error("DOCTYPE declarations are not supported");
  };
  xml.onopentag = (tag): void => {
    if (path.length === 32) throw new Error("VSIX manifest exceeds 32 nested elements");
    path.push(tag.name.split(":").at(-1) ?? "");
    root ??= path[0];
    if (path.join("/") !== "PackageManifest/Metadata/Properties/Property") return;
    addVsixProperty(tag, links, file);
  };
  xml.onclosetag = (): void => {
    path.pop();
  };
  xml.write(buffer.toString("utf8")).close();
  if (root !== "PackageManifest") throw new Error("VSIX metadata requires a PackageManifest root");
  return links;
}

/** Read source links from the extension's root package and VSIX metadata without network access. */
export function collectRepositoryLinks(contents: VsixContents): RepositoryLinks {
  const result = packageRepository(contents);
  const manifest = [...contents.files].find(
    ([file]) => file.toLowerCase() === "extension.vsixmanifest",
  );
  if (manifest === undefined) {
    const skipped = contents.artifacts?.some(
      (entry) =>
        entry.skipped &&
        (entry.path ?? entry.originalPath).toLowerCase() === "extension.vsixmanifest",
    );
    if (skipped === true) {
      result.warnings.push(
        "Cannot check source links: VSIX metadata was skipped. Inspect the archive.",
      );
    }
    return result;
  }
  const [file, buffer] = manifest;
  try {
    result.links.push(...vsixRepositoryLinks(file, buffer));
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid XML";
    result.warnings.push(`Cannot check ${file} source links: ${reason}. Inspect the metadata.`);
  }
  return result;
}

function githubUrl(value: string): URL {
  const normalized = value
    .replace(/^github:/i, "https://github.com/")
    .replace(/^git@github\.com:/i, "https://github.com/")
    .replace(/^git\+/i, "");
  return new URL(normalized.includes("://") ? normalized : `https://github.com/${normalized}`);
}

function supportedGithubUrl(url: URL): boolean {
  if (url.hostname !== "github.com" && url.hostname !== "www.github.com") return false;
  if (url.password !== "") return false;
  if (url.protocol === "ssh:") return url.username === "git" && ["", "22"].includes(url.port);
  if (url.port !== "") return false;
  return ["https:", "http:", "git:"].includes(url.protocol) && url.username === "";
}

function hasUnsafeCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return /\s/u.test(value);
}

/** Normalize GitHub web, npm shorthand, and Git SSH links without fetching the declared URL. */
export function parseGitHubRepository(value: string): GitHubRepository | null {
  const trimmed = value.trim();
  if (trimmed.length > 2048 || hasUnsafeCharacters(trimmed)) return null;
  try {
    const url = githubUrl(trimmed);
    if (!supportedGithubUrl(url)) return null;
    return repositoryPath(url.pathname);
  } catch {
    return null;
  }
}

function repositoryPath(path: string): GitHubRepository | null {
  const [, ownerPart, namePart] = path.split("/");
  if (ownerPart === undefined || namePart === undefined) return null;
  const owner = decodeURIComponent(ownerPart).toLowerCase();
  const name = decodeURIComponent(namePart)
    .replace(/\.git$/i, "")
    .toLowerCase();
  if (!/^[a-z\d][a-z\d-]{0,38}$/.test(owner)) return null;
  if (!/^[a-z\d_.-]{1,100}$/.test(name) || name === "." || name === "..") return null;
  return { owner, name, url: `https://github.com/${owner}/${name}` };
}
