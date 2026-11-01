import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "..");

describe("production package", () => {
  it("publishes no compiled tests and keeps type packages out of runtime dependencies", async () => {
    const result = spawnSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json"], {
      cwd: root,
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, npm_config_cache: join(root, ".cache", "npm") },
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const packages = JSON.parse(result.stdout) as Array<{ files: Array<{ path: string }> }>;
    const files = packages.flatMap((entry) => entry.files.map((file) => file.path));
    expect(files).toContain("dist/index.js");
    expect(files.some((file) => /\.test\./.test(file))).toBe(false);
    const metadata = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    expect(Object.keys(metadata.dependencies).some((name) => name.startsWith("@types/"))).toBe(
      false,
    );
    expect(metadata.devDependencies["@types/yauzl"]).toBeDefined();
  });
});
