// Unit tests (pnpm test): Node, a hand-written fake `chrome` (test/chrome.ts) installed before each file.
import { defineConfig } from "vitest/config";

export default defineConfig({
  // One React, as in build.mjs: the shared web components must use this package's copy.
  resolve: { alias: { "@web": new URL("../web/src", import.meta.url).pathname }, dedupe: ["react", "react-dom"] },
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    setupFiles: ["test/setup.ts"],
    restoreMocks: true,
  },
});
