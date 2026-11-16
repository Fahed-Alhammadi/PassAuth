import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { version } from "./package.json";

export default defineConfig({
  plugins: [react()],
  // Sent as `X-PassAuth-Client: web/<version>` (src/lib/platform.ts).
  define: { __PASSAUTH_WEB_VERSION__: JSON.stringify(version) },
  build: { target: "es2022", sourcemap: false, assetsInlineLimit: 0 },
  server: {
    port: 5173,
    proxy: {
      "/api/ws": { target: "ws://localhost:8080", ws: true },
      "/api": "http://localhost:8080",
    },
  },
});
