import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: { "#internal": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    globals: false,
    environment: "node",
    include: ["src/**/*.corpus.test.ts"],
    maxWorkers: 1,
    testTimeout: 60_000,
  },
});
