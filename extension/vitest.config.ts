// Unit tests (pnpm test): Node, a hand-written fake `chrome` (test/chrome.ts) installed before each file.
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "@web": new URL("../web/src", import.meta.url).pathname } },
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    setupFiles: ["test/setup.ts"],
    restoreMocks: true,
  },
});
