import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

// The PassAuth push relay (see README.md). Deployed with `npm run deploy`; the Apple key is a secret
// (`APNS_KEY_P8`), never in this file. The address below is built into every PassAuth server as the default relay:
// never change it.
export default defineConfig({
	worker: {
		name: "passauth-push",
		compatibilityDate: "2026-11-17",
		entrypoint,
		domains: ["passauth-push.uaealhammadi.com"],
		workersDev: false,
		previewUrls: false,
		observability: { enabled: true },
		env: {
			APNS_KEY_P8: bindings.secret(),
			APNS_KEY_ID: bindings.text("W7Q88F4698"),
			APNS_TEAM_ID: bindings.text("JEXQBK3SQ5"),
			APNS_TOPIC: bindings.text("io.passauth.app"),
			// At most 3 alerts a minute for one device; 300 requests a minute from one server address.
			TOKEN_LIMIT: bindings.rateLimit({ namespace: "7301", simple: { limit: 3, period: 60 } }),
			IP_LIMIT: bindings.rateLimit({ namespace: "7302", simple: { limit: 300, period: 60 } }),
		},
	},
});
