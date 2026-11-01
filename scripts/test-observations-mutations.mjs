import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("..", import.meta.url));
const unit = [
  "src/scanner/observations.test.ts",
  "src/scanner/observed-values.test.ts",
  "src/scanner/capabilities.test.ts",
  "src/scanner/checks/finding-quality.test.ts",
  "src/scanner/clean-corpus.test.ts",
];
const cli = ["--config", "vitest.cli.config.ts", "src/behavior.smoke.test.ts"];

/**
 * @typedef {{name: string, file: string, before: string,
 *   after: string, cli?: boolean}} Mutation
 */
/** @type {Mutation[]} */
const mutations = [
  ...[
    "network-request",
    "file-read",
    "file-write",
    "process-execution",
    "code-execution",
    "credential-access",
    "dynamic-call",
  ].map((kind) => ({
    name: `drop ${kind} observations`,
    file: "src/scanner/observations.ts",
    before: "const operation = OPERATIONS.get(api);",
    after: `const operation = OPERATIONS.get(api); if (operation?.kind === "${kind}") return;`,
  })),
  {
    name: "lose unresolved arguments",
    file: "src/scanner/observed-values.ts",
    before:
      'const unresolved: ObservedValue = {\n    kind: "unresolved",\n' +
      "    expression: source.slice(node.start, node.end).slice(0, 200),\n  };",
    after: 'const unresolved: ObservedValue = {kind: "literal", value: "guessed"};',
  },
  {
    name: "misreport source columns",
    file: "src/scanner/observations.ts",
    before: "column: offsetToColumn(span.start, this.lines) + 1,",
    after: "column: 1,",
  },
  {
    name: "collapse distinct calls on one line",
    file: "src/scanner/observations.ts",
    before: "this.observations.push({",
    after:
      "if (this.observations.some(item => item.kind === operation.kind && " +
      "item.location.line === offsetToLine(span.start, this.lines))) return; " +
      "this.observations.push({",
  },
  {
    name: "ignore lexical shadowing",
    file: "src/scanner/source-bindings.ts",
    before: "this.scopes.get(node) ?? this.root",
    after: "this.root",
  },
  {
    name: "misattribute unrelated eval methods",
    file: "src/scanner/source-bindings.ts",
    before: "resolve(node: Node): string | null {",
    after:
      'resolve(node: Node): string | null { if (node.type === "MemberExpression" && ' +
      'propertyName(node.property, node.computed) === "eval") return "global.eval";',
  },
  {
    name: "filter facts with severity",
    file: "src/scanner/index.ts",
    before: "    observations,",
    after: '    observations: options.severity === "critical" ? [] : observations,',
  },
  {
    name: "drop module-load observations",
    file: "src/scanner/observations.ts",
    before: "this.observations.push({",
    after: 'if (operation.kind === "module-load") return; this.observations.push({',
  },
  {
    name: "invent a trusted destination",
    file: "src/scanner/observed-values.ts",
    before: 'return value.length <= 4096 ? { kind: "literal", value } : undefined;',
    after: 'return {kind: "literal", value: "https://trusted.example.invalid"};',
  },
  {
    name: "accept missing analyzers in the clean corpus",
    file: "src/scanner/clean-corpus.ts",
    before: "const files = entry.unanalyzedFiles ?? [];",
    after: 'if (entry.id !== "") return; const files = entry.unanalyzedFiles ?? [];',
  },
  {
    name: "discard capability evidence",
    file: "src/scanner/capabilities.ts",
    before: "evidence: matching.map(evidence),",
    after: "evidence: [],",
  },
  {
    name: "discard SARIF observations",
    file: "src/formatters.ts",
    cli: true,
    before: "observations: result.observations,",
    after: "observations: [],",
  },
  {
    name: "discard SARIF coverage failures",
    file: "src/formatters.ts",
    cli: true,
    before: "sarifCoverage(run, result.metadata.coverage);",
    after: "// mutation: omit failure diagnostics",
  },
  {
    name: "hide source observations in text",
    file: "src/formatters.ts",
    cli: true,
    before: "printObservations(result.observations);",
    after: "// mutation: omit source observations",
  },
];

/** @param {string} root @param {string[]} args */
function run(root, args) {
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0" },
  });
  if (result.error !== undefined) throw result.error;
  return { status: result.status, output: result.stdout + result.stderr };
}

/** @param {string} root */
function build(root) {
  const result = run(root, ["node_modules/typescript/bin/tsc", "--project", "tsconfig.build.json"]);
  if (result.status !== 0) throw new Error(`Mutation fixture did not compile:\n${result.output}`);
}

/** @param {string} root @param {string[]} targets */
function tests(root, targets) {
  return run(root, ["node_modules/vitest/vitest.mjs", "run", ...targets, "--reporter=dot"]);
}

/** @param {string} root @param {Mutation} mutation */
async function checkMutation(root, mutation) {
  const target = join(root, mutation.file);
  const source = await readFile(target, "utf8");
  if (!source.includes(mutation.before)) throw new Error(`Stale mutation anchor: ${mutation.name}`);
  await writeFile(target, source.replace(mutation.before, mutation.after));
  try {
    build(root);
    const result = tests(root, mutation.cli === true ? cli : unit);
    if (
      result.status !== 1 ||
      !result.output.includes(" FAIL ") ||
      result.output.includes("Failed Suites")
    ) {
      throw new Error(
        `Mutation survived or failed before test assertions: ${mutation.name}\n${result.output}`,
      );
    }
    console.log(`caught: ${mutation.name}`);
  } finally {
    await writeFile(target, source);
  }
}

async function main() {
  const root = await mkdtemp(join(tmpdir(), "vsix-behavior-mutations-"));
  try {
    for (const entry of [
      "src",
      "zoo",
      "test-corpus/behavior",
      "test-corpus/clean/manifest.json",
      "package.json",
      "tsconfig.json",
      "tsconfig.build.json",
      "vitest.config.ts",
      "vitest.cli.config.ts",
    ]) {
      await mkdir(join(root, entry, ".."), { recursive: true });
      await cp(join(repo, entry), join(root, entry), { recursive: true });
    }
    await symlink(join(repo, "node_modules"), join(root, "node_modules"), "dir");
    build(root);
    for (const targets of [unit, cli]) {
      const baseline = tests(root, targets);
      if (baseline.status !== 0)
        throw new Error(`Unmodified acceptance tests failed:\n${baseline.output}`);
    }
    for (const mutation of mutations) await checkMutation(root, mutation);
    console.log(`All ${mutations.length} behavior mutations were caught.`);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

await main();
