import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);

it("reads a million string matches within a bounded heap", async () => {
  const root = await mkdtemp(join(tmpdir(), "vsix-yara-memory-"));
  const module = pathToFileURL(
    join(import.meta.dirname, "..", "dist", "scanner", "checks", "yara-output.js"),
  );
  const script = join(root, "evidence.mjs");
  await writeFile(
    script,
    `
import assert from "node:assert/strict";
import { createYaraOutputReader } from ${JSON.stringify(module.href)};
let result;
const reader = createYaraOutputReader(value => { result = value; }, error => { throw error; });
reader.write(Buffer.from('{"path":"fixture.js","rules":[{"strings":['));
const match = JSON.stringify({identifier:"$a",offset:0,match:"sentinel"});
const chunk = Buffer.from((match + ",").repeat(1000));
for (let index = 0; index < 1000; index++) {
  reader.write(chunk);
  if (process.memoryUsage().heapUsed > 64 * 1024 * 1024) {
    throw new Error("YARA evidence exceeded its memory bound");
  }
}
reader.write(Buffer.from(match + "]}]}"));
reader.end();
assert.equal(result.rules[0].totalMatches,1000001);
assert.equal(result.rules[0].strings.length,20);
console.log("bounded evidence verified");
`,
  );
  try {
    const result = await execute(process.execPath, ["--max-old-space-size=96", script], {
      timeout: 30_000,
    });
    expect(result.stdout).toContain("bounded evidence verified");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}, 35_000);
