import {
  collectRepositoryLinks,
  parseGitHubRepository,
} from "#internal/scanner/repository-links.js";
import type { GitHubRepository, RepositoryLink } from "#internal/scanner/repository-links.js";
import { createGitHubLookup } from "#internal/scanner/repository-github.js";
import type { GitHubLookup, GitHubResult } from "#internal/scanner/repository-github.js";
import type { CheckResult, Finding, VsixContents } from "#internal/scanner/types.js";

export type RepositoryCheck = (contents: VsixContents) => Promise<CheckResult>;

const TITLES = {
  REPOSITORY_LINK_MISSING: "No source repository is declared",
  REPOSITORY_EMPTY: "Declared source repository contains no commits",
  REPOSITORY_UNAVAILABLE: "Declared source repository is inaccessible",
  REPOSITORY_OWNER_UNAVAILABLE: "Declared source repository owner is inaccessible",
} as const;

function repositoryFinding(
  id: keyof typeof TITLES,
  description: string,
  link?: RepositoryLink,
  repository?: GitHubRepository,
): Finding {
  return {
    id,
    title: TITLES[id],
    description,
    severity: "low",
    category: "metadata",
    location: { file: link?.file ?? "package.json" },
    metadata: {
      ...(link === undefined ? {} : { field: link.field }),
      ...(repository === undefined ? {} : { repo: repository.url }),
    },
  };
}

function isEmptyRepository(response: GitHubResult): boolean {
  if ("error" in response) return false;
  if (response.status === 200) return Array.isArray(response.data) && response.data.length === 0;
  const data = response.data;
  return (
    response.status === 409 &&
    typeof data === "object" &&
    data !== null &&
    "message" in data &&
    data.message === "Git Repository is empty."
  );
}

function hasCommits(response: GitHubResult): boolean {
  if ("error" in response || response.status !== 200 || !Array.isArray(response.data)) return false;
  const first: unknown = response.data[0];
  return (
    typeof first === "object" &&
    first !== null &&
    "sha" in first &&
    typeof first.sha === "string" &&
    /^[a-f\d]{40}$/i.test(first.sha)
  );
}

function ownerWarning(owner: GitHubResult): string | null {
  if ("error" in owner) return owner.error;
  if (owner.status === 404) return null;
  const data = owner.data;
  if (
    owner.status === 200 &&
    typeof data === "object" &&
    data !== null &&
    "login" in data &&
    typeof data.login === "string"
  )
    return null;
  return "unexpected GitHub response; inspect the owner manually";
}

async function unavailableRepository(
  lookup: GitHubLookup,
  link: RepositoryLink,
  repository: GitHubRepository,
): Promise<CheckResult> {
  const owner = await lookup(`/users/${repository.owner}`);
  const missingOwner = !("error" in owner) && owner.status === 404;
  const id = missingOwner ? "REPOSITORY_OWNER_UNAVAILABLE" : "REPOSITORY_UNAVAILABLE";
  const subject = missingOwner ? `GitHub owner ${repository.owner}` : repository.url;
  const warning = ownerWarning(owner);
  const description =
    `${subject} is not accessible to this request. It may be missing or private. ` +
    "Check the publisher's declared source repository manually.";
  return {
    findings: [repositoryFinding(id, description, link, repository)],
    warnings: warning === null ? [] : [`Cannot verify ${repository.url} owner: ${warning}.`],
  };
}

async function checkLink(
  lookup: GitHubLookup,
  link: RepositoryLink,
  repository: GitHubRepository,
): Promise<CheckResult> {
  const response = await lookup(`/repos/${repository.owner}/${repository.name}/commits?per_page=1`);
  if (isEmptyRepository(response)) {
    return {
      findings: [
        repositoryFinding(
          "REPOSITORY_EMPTY",
          `${repository.url} contains no commits. Review the declared source.`,
          link,
          repository,
        ),
      ],
      warnings: [],
    };
  }
  if (hasCommits(response)) return { findings: [], warnings: [] };
  if (!("error" in response) && response.status === 404) {
    return unavailableRepository(lookup, link, repository);
  }
  const reason =
    "error" in response ? response.error : "unexpected GitHub response; inspect manually";
  return { findings: [], warnings: [`Cannot verify ${repository.url}: ${reason}.`] };
}

/** Create an opt-in check that shares GitHub requests for the lifetime of a scan or batch. */
export function createRepositoryCheck(): RepositoryCheck {
  const lookup = createGitHubLookup();
  return async (contents): Promise<CheckResult> => {
    const { links, warnings } = collectRepositoryLinks(contents);
    const findings: Finding[] = [];
    if (links.length === 0 && warnings.length === 0) {
      findings.push(
        repositoryFinding(
          "REPOSITORY_LINK_MISSING",
          "The extension declares no source repository. " +
            "Review the publisher; source disclosure is optional.",
        ),
      );
    }
    const seen = new Set<string>();
    for (const link of links) {
      const repository = parseGitHubRepository(link.value);
      if (repository === null) {
        warnings.push(
          `Cannot verify ${link.file} ${link.field}; check the GitHub link or inspect manually.`,
        );
        continue;
      }
      if (seen.has(repository.url)) continue;
      seen.add(repository.url);
      const result = await checkLink(lookup, link, repository);
      findings.push(...result.findings);
      warnings.push(...result.warnings);
    }
    return { findings, warnings };
  };
}
