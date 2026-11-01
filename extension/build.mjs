// Builds the extension into dist/: popup, inline menu, offscreen clipboard + background (ES modules, WASM as a
// file) and the two content scripts (classic IIFE bundles).
import { build } from "vite";
import react from "@vitejs/plugin-react";
import { cpSync, rmSync } from "node:fs";

// dedupe: shared web components must use this package's single React copy.
const base = {
  configFile: false,
  logLevel: "warn",
  resolve: { alias: { "@web": new URL("../web/src", import.meta.url).pathname }, dedupe: ["react", "react-dom"] },
};
rmSync("dist", { recursive: true, force: true });

await build({
  ...base,
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
    target: "es2022",
    assetsInlineLimit: 0,
    modulePreload: false,
    rollupOptions: {
      input: { popup: "popup.html", "inline-menu": "inline-menu.html", offscreen: "offscreen.html", background: "src/background/index.ts" },
      output: { entryFileNames: "[name].js", chunkFileNames: "chunks/[name]-[hash].js", assetFileNames: "assets/[name]-[hash][extname]" },
    },
  },
});

for (const [entry, name] of [["src/content/index.ts", "content"], ["src/page/webauthn.ts", "webauthn"]]) {
  await build({
    ...base,
    build: {
      outDir: "dist",
      emptyOutDir: false,
      target: "es2022",
      lib: { entry, formats: ["iife"], name: `passauth_${name}`, fileName: () => `${name}.js` },
    },
  });
}

cpSync("public", "dist", { recursive: true });
console.log("built extension in dist/");
