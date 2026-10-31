import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkYara } from "#internal/scanner/checks/yara.js";

const failures = vi.hoisted(() => ({ write: false, cleanup: false, leftovers: [] as string[] }));
vi.mock("node:fs/promises", async (original) => {
  const fs = await original<typeof import("node:fs/promises")>();
  return {
    ...fs,
    writeFile: async (...args: Parameters<typeof fs.writeFile>): Promise<void> => {
      if (failures.write && typeof args[0] === "string" && args[0].endsWith("main.js"))
        throw new Error("Write denied");
      await fs.writeFile(...args);
    },
    rm: async (...args: Parameters<typeof fs.rm>): Promise<void> => {
      if (failures.cleanup && String(args[0]).includes("vsix-audit-")) {
        failures.leftovers.push(String(args[0]));
        throw new Error("Cleanup denied");
      }
      await fs.rm(...args);
    },
  };
});

interface ProcessFixture {
  record?: unknown;
  stdout?: string;
  stderr?: string;
  status?: number;
  versionStatus?: number;
}

let root = "";
let rules = "";
const contents = {
  manifest: { name: "fixture", version: "1.0.0" },
  basePath: "/fixture",
  files: new Map([["main.js", Buffer.from("sentinel")]]),
};

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "vsix-yara-process-"));
  rules = join(root, "rules");
  await mkdir(rules);
  await writeFile(join(rules, "fixture.yar"), "rule Fixture { condition: true }");
  const executable = join(root, "yr");
  await writeFile(
    executable,
    `#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
const fixture = JSON.parse(readFileSync(process.env.VSIX_YARA_PROCESS_FIXTURE, "utf8"));
if (process.argv.includes("--version")) {
  console.log("yara-x-cli fixture");
  process.exit(fixture.versionStatus ?? 0);
}
const directory = process.argv.at(-1);
const rules = process.argv.at(-2);
const record = fixture.record ?? { path: "$TARGET/main.js", rules: [{ identifier: "Fixture",
  namespace: "$RULES/fixture.yar", meta: [["severity", "critical"], ["capabilities", "execution"]] }] };
if (typeof record.path === "string") record.path = record.path.replace("$TARGET", directory);
for (const rule of Array.isArray(record.rules) ? record.rules : []) {
  if (typeof rule.namespace === "string") rule.namespace = rule.namespace.replace("$RULES", rules);
}
process.stdout.write(fixture.stdout ?? JSON.stringify(record) + "\\n");
process.stderr.write(fixture.stderr ?? "");
process.exit(fixture.status ?? 0);
`,
  );
  await chmod(executable, 0o755);
  vi.stubEnv("PATH", `${root}${delimiter}${process.env["PATH"] ?? ""}`);
  vi.stubEnv("VSIX_YARA_PROCESS_FIXTURE", join(root, "process.json"));
});

afterEach(async () => {
  failures.write = false;
  failures.cleanup = false;
  vi.unstubAllEnvs();
  for (const directory of failures.leftovers.splice(0))
    await rm(directory, { recursive: true, force: true });
  await rm(root, { recursive: true, force: true });
});

async function run(fixture: ProcessFixture = {}): ReturnType<typeof checkYara> {
  await writeFile(join(root, "process.json"), JSON.stringify(fixture));
  return checkYara(contents, rules);
}

describe("YARA-X process boundary", () => {
  it("retains valid rules on both sides of malformed rule metadata", async () => {
    const result = await run({
      record: {
        path: "$TARGET/main.js",
        rules: [
          { identifier: "Before", namespace: "$RULES/a.yar", meta: [["severity", "high"]] },
          { identifier: "Broken", namespace: "$RULES/a.yar", meta: [] },
          { identifier: "After", namespace: "$RULES/a.yar", meta: [["severity", "critical"]] },
        ],
      },
    });
    expect(result.findings.map((finding) => finding.id)).toEqual(
      expect.arrayContaining(["YARA_Before", "YARA_After", "YARA_OUTPUT_ERROR"]),
    );
    expect(result.warnings).toHaveLength(1);
  });

  it("preserves partial matches when the process fails", async () => {
    const result = await run({ status: 1, stderr: "Rule scan failed" });
    expect(result.findings).toContainEqual(
      expect.objectContaining({ id: "YARA_Fixture", severity: "critical" }),
    );
    expect(result.warnings.join(" ")).toContain("Rule scan failed");
  });

  it("retains diagnostics as explicit coverage warnings", async () => {
    expect((await run({ stderr: "warning: rule incomplete" })).warnings.join(" ")).toContain(
      "rule incomplete",
    );
  });

  it("reports a missing or broken executable", async () => {
    const result = await run({ versionStatus: 1 });
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "YARA_NOT_INSTALLED" }));
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it.each([
    { stdout: "{" },
    { record: { path: "$TARGET/main.js", rules: 42 } },
    { record: { path: "$TARGET/main.js", rules: [{}] } },
    {
      record: {
        path: "$TARGET/main.js",
        rules: [{ identifier: "Bad", namespace: "$RULES/a.yar", meta: 42 }],
      },
    },
    {
      record: {
        path: "$TARGET/main.js",
        rules: [{ identifier: "Bad", namespace: "$RULES/a.yar", meta: [[42, "bad"]] }],
      },
    },
    {
      record: {
        path: "$TARGET/main.js",
        rules: [{ identifier: "Bad", namespace: "$RULES/a.yar", meta: [["severity", "invalid"]] }],
      },
    },
    {
      record: {
        path: "$TARGET/main.js",
        rules: [
          {
            identifier: "Bad",
            namespace: "$RULES/a.yar",
            meta: [
              ["severity", "high"],
              ["capabilities", 42],
            ],
          },
        ],
      },
    },
    {
      record: {
        path: "$TARGET/main.js",
        rules: [
          {
            identifier: "Bad",
            namespace: "$RULES/a.yar",
            meta: [
              ["severity", "high"],
              ["capabilities", "unknown"],
            ],
          },
        ],
      },
    },
    { record: { path: "$TARGET/../outside.js", rules: [] } },
  ])("reports malformed process output %j", async (fixture) => {
    const result = await run(fixture);
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "YARA_OUTPUT_ERROR" }));
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it("reports file preparation failures", async () => {
    failures.write = true;
    expect((await run()).warnings.join(" ")).toContain("Write denied");
  });

  it("retains matches and reports cleanup failures", async () => {
    failures.cleanup = true;
    const result = await run();
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "YARA_Fixture" }));
    expect(result.warnings.join(" ")).toContain("Cleanup denied");
  });

  it("reports skipped unsafe paths", async () => {
    await writeFile(join(root, "process.json"), "{}");
    const result = await checkYara(
      { ...contents, files: new Map([["../outside.js", Buffer.from("sentinel")]]) },
      rules,
    );
    expect(result.findings).toContainEqual(expect.objectContaining({ id: "YARA_SKIPPED_FILE" }));
  });
});
