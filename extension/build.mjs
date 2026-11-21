// Builds the extension into dist/: popup, inline menu, save prompt, offscreen clipboard + background (ES modules, WASM as a
// file) and the content scripts (classic IIFE bundles): the document_start passkey bridge (bridge.js) and the WebAuthn
// shim (webauthn.js, page world), and the main content script at document_idle (content.js).
// `node build.mjs --firefox` builds the Firefox version into dist-firefox/ instead: the same code with the manifest
// from firefox-manifest.mjs and no offscreen page (Firefox's background has a DOM).
// `node build.mjs --safari` builds the Safari version (inside the iOS app) into dist-safari/: the manifest from
// safari-manifest.mjs with the Safari app's version (safari/VERSION), no offscreen page and no passkey scripts.

import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import react from "@vitejs/plugin-react";
import { build } from "vite";
import { firefoxManifest } from "./firefox-manifest.mjs";
import { safariManifest } from "./safari-manifest.mjs";

const firefox = process.argv.includes("--firefox");
const safari = process.argv.includes("--safari");
const OUT = firefox ? "dist-firefox" : safari ? "dist-safari" : "dist";
// Firefox's and Safari's backgrounds are event pages with a DOM: no offscreen clipboard page.
const offscreen = !firefox && !safari;

// dedupe: shared web components must use this package's single React copy.
const base = {
  configFile: false,
  logLevel: "warn",
  resolve: { alias: { "@web": new URL("../web/src", import.meta.url).pathname }, dedupe: ["react", "react-dom"] },
};
rmSync(OUT, { recursive: true, force: true });

await build({
  ...base,
  plugins: [react()],
  base: "./",
  build: {
    outDir: OUT,
    target: "es2022",
    assetsInlineLimit: 0,
    modulePreload: false,
    rollupOptions: {
      input: {
        popup: "popup.html",
        "inline-menu": "inline-menu.html",
        "save-prompt": "save-prompt.html",
        ...(offscreen ? { offscreen: "offscreen.html" } : {}),
        background: "src/background/main.ts",
      },
      output: { entryFileNames: "[name].js", chunkFileNames: "chunks/[name]-[hash].js", assetFileNames: "assets/[name]-[hash][extname]" },
    },
  },
});

const contentScripts = [
  ["src/content/bridge.ts", "bridge"],
  ["src/content/index.ts", "content"],
  ["src/page/webauthn.ts", "webauthn"],
].filter(([, name]) => !safari || name === "content");
for (const [entry, name] of contentScripts) {
  await build({
    ...base,
    build: {
      outDir: OUT,
      emptyOutDir: false,
      target: "es2022",
      lib: { entry, formats: ["iife"], name: `passauth_${name}`, fileName: () => `${name}.js` },
    },
  });
}

cpSync("public", OUT, { recursive: true });
const chromeManifest = () => JSON.parse(readFileSync("public/manifest.json", "utf8"));
const writeManifest = (m) => writeFileSync(`${OUT}/manifest.json`, `${JSON.stringify(m, null, 2)}\n`);
if (firefox) writeManifest(firefoxManifest(chromeManifest()));
if (safari) writeManifest(safariManifest(chromeManifest(), readFileSync("../safari/VERSION", "utf8").trim()));
console.log(`built ${firefox ? "Firefox " : safari ? "Safari " : ""}extension in ${OUT}/`);
