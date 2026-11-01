import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  collectRepositoryLinks,
  parseGitHubRepository,
} from "#internal/scanner/repository-links.js";
import type { VsixContents } from "#internal/scanner/types.js";

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

function metadata(properties: string): string {
  return (
    `<PackageManifest><Metadata><Properties>${properties}</Properties>` +
    "</Metadata></PackageManifest>"
  );
}

const sourceId = "Microsoft.VisualStudio.Services.Links.Source";
const source = `<Property Id="${sourceId}" Value="https://github.com/example/source"/>`;

describe("declared source links", () => {
  it.each(["example/source", { type: "git", url: "example/source", directory: "extension" }])(
    "reads the root package repository %j",
    (repository) => {
      expect(collectRepositoryLinks(contents(repository))).toEqual({
        links: [{ value: "example/source", file: "package.json", field: "repository" }],
        warnings: [],
      });
    },
  );

  it.each([null, false, 7, [], {}, { url: 7 }, "", "   "])(
    "reports malformed repository metadata %j",
    (repository) => {
      expect(collectRepositoryLinks(contents(repository))).toMatchObject({
        links: [],
        warnings: [expect.stringContaining("package.json repository")],
      });
    },
  );

  it("reads namespaced VSIX properties, single quotes, and encoded attribute values", () => {
    const xml = `<v:PackageManifest xmlns:v="urn:test"><v:Metadata><v:Properties>
      <v:Property Id='${sourceId}' Value='https://github.com/example/source?x=1&amp;y=2'/>
      <v:Property Id='Microsoft.VisualStudio.Services.Links.GitHub' Value='example/other'/>
      </v:Properties></v:Metadata></v:PackageManifest>`;
    expect(collectRepositoryLinks(contents("example/root", xml))).toMatchObject({
      links: [
        { field: "repository" },
        { field: sourceId, value: "https://github.com/example/source?x=1&y=2" },
        { field: "Microsoft.VisualStudio.Services.Links.GitHub", value: "example/other" },
      ],
      warnings: [],
    });
  });

  it("ignores comments, unrelated properties, and properties outside metadata", () => {
    const xml = `<PackageManifest><!-- ${source} --><Assets>${source}</Assets>
      <Metadata><Properties><Property Id="Other" Value="example/other"/></Properties></Metadata>
      </PackageManifest>`;
    expect(collectRepositoryLinks(contents(undefined, xml))).toEqual({ links: [], warnings: [] });
  });

  it.each([
    "",
    "<Other/>",
    metadata(source).slice(0, -5),
    `<!DOCTYPE x SYSTEM "https://example.invalid/entity">${metadata(source)}`,
    metadata(`<Property Id="${sourceId}" Value="example/&nbsp;"/>`),
    metadata(`<Property Id="${sourceId}" Value=""/>`),
    metadata(source.repeat(9)),
    "x".repeat(1024 * 1024 + 1),
    `<PackageManifest>${"<x>".repeat(40)}${"</x>".repeat(40)}</PackageManifest>`,
  ])("reports malformed or excessive XML without trusting partial source links", (xml) => {
    const result = collectRepositoryLinks(contents(undefined, xml));
    expect(result.links).toEqual([]);
    expect(result.warnings).toHaveLength(1);
  });

  it("does not claim a missing repository when VSIX source metadata was skipped", () => {
    const input = contents();
    input.artifacts = [
      {
        originalPath: "extension.vsixmanifest",
        path: "extension.vsixmanifest",
        size: 0,
        skipped: true,
        skipReason: "too large",
      },
    ];
    expect(collectRepositoryLinks(input)).toMatchObject({
      links: [],
      warnings: [expect.stringContaining("skipped")],
    });
  });

  it("round-trips XML attribute entities in generated source URLs", () => {
    const characters = fc.array(fc.constantFrom(..."ab19&<>\"'".split("")), { maxLength: 30 });
    fc.assert(
      fc.property(characters, (value) => {
        const url = `https://github.com/example/source?q=${value.join("")}`;
        const escaped = url
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&apos;");
        const xml = metadata(`<Property Id="${sourceId}" Value="${escaped}"/>`);
        expect(collectRepositoryLinks(contents(undefined, xml)).links[0]?.value).toBe(url);
      }),
    );
  });
});

describe("GitHub URL normalization", () => {
  it.each([
    "Example/Source",
    "github:Example/Source",
    "https://github.com/Example/Source",
    "git+https://github.com/Example/Source.git#main",
    "git@github.com:Example/Source.git",
    "ssh://git@github.com/Example/Source.git",
    "git+ssh://git@github.com:22/Example/Source.git",
    "http://www.github.com/Example/Source/",
    "git://github.com/Example/Source.git",
    "https://github.com/Example/Source/tree/main/extension?tab=readme",
  ])("normalizes %s", (url) => {
    expect(parseGitHubRepository(url)).toEqual({
      owner: "example",
      name: "source",
      url: "https://github.com/example/source",
    });
  });

  it.each([
    "",
    "https://gitlab.com/example/source",
    "https://github.com.evil.test/example/source",
    "https://github.com@evil.test/example/source",
    "https://127.0.0.1/example/source",
    "https://github.com:444/example/source",
    "file:///example/source",
    "javascript:alert(1)",
    "https://user:secret@github.com/example/source",
    "ssh://user@github.com/example/source",
    "https://github.com/example",
    "https://github.com/example/%2fsource",
    "https://github.com/example/%ZZ",
    "https://github.com/example/so urce",
    "https://github.com/example/so\nurce",
    "x".repeat(2049),
  ])("leaves unsafe or unsupported link %j unverified", (url) => {
    expect(parseGitHubRepository(url)).toBeNull();
  });

  it("normalizes generated shorthand, SSH, and web links to the same repository", () => {
    const name = fc
      .array(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789".split("")), {
        minLength: 1,
        maxLength: 30,
      })
      .map((characters) => characters.join(""));
    fc.assert(
      fc.property(name, name, (owner, repository) => {
        const expected = `https://github.com/${owner}/${repository}`;
        const urls = [
          expected,
          `${owner}/${repository}`,
          `git@github.com:${owner}/${repository}.git`,
        ];
        expect(urls.map((url) => parseGitHubRepository(url)?.url)).toEqual([
          expected,
          expected,
          expected,
        ]);
      }),
    );
  });

  it("keeps fuzzed text inside canonical GitHub repository URLs", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4096 }), (value) => {
        const result = parseGitHubRepository(value);
        expect(
          result === null || /^https:\/\/github\.com\/[a-z\d-]+\/[a-z\d_.-]+$/.test(result.url),
        ).toBe(true);
      }),
      { numRuns: 1000 },
    );
  });
});
