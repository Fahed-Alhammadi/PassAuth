import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const at = (path: string) => new URL(path, import.meta.url).pathname;

// dedupe: components shared from web/src must use this package's single React copy.
export default defineConfig({
  plugins: [react()],
  base: "./",
  clearScreen: false,
  resolve: { alias: { "@web": at("../web/src") }, dedupe: ["react", "react-dom"] },
  build: { target: "es2022", sourcemap: false, assetsInlineLimit: 0 },
  // The dev server may serve only the two source trees; never anything under Keys/ or a key file.
  server: {
    port: 1420,
    strictPort: true,
    fs: { allow: [at("../web/src"), at("../web/public"), at(".")], deny: ["**/Keys/**", "**/*.{p12,jks,p8,key,pem}"] },
  },
});
