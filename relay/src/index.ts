/**
 * PassAuth push relay. Self-hosted PassAuth servers can't hold the app publisher's Apple push key, so they ask this
 * relay to wake one device up: `POST /v1/notify {platform, token, environment, kind}`. For `apns` the relay signs with
 * the key and sends Apple a fixed alert ("Sign-in request … Open PassAuth to review."); for `fcm` (Android) it sends
 * Firebase a data-only message `{kind: "auth_request"}` and the app shows the same fixed notice.
 *
 * It stores nothing and never sees an account, an email or a server's data: only the device's push token and when to
 * send. Limits: a token gets at most a few alerts a minute, an address a few hundred (Cloudflare rate limiting).
 *
 * Answers (the server's contract): 202 sent · 410 unregistered (the server forgets the token) · 400 bad_request ·
 * 413 too_large · 429 rate_limited · 502 upstream.
 */
import { type ApnsConfig, type Environment, JwtCache, type Outcome, sendAlert } from "./apns";
import { AccessTokenCache, parseServiceAccount, sendFcm } from "./fcm";

interface Limiter {
	limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
	APNS_KEY_P8: string;
	APNS_KEY_ID: string;
	APNS_TEAM_ID: string;
	APNS_TOPIC: string;
	/** The Firebase service account's JSON (FCM HTTP v1). Without it, `fcm` requests answer 502. */
	FCM_SERVICE_ACCOUNT?: string;
	/** Per device token. */
	TOKEN_LIMIT: Limiter;
	/** Per calling address (a PassAuth server). */
	IP_LIMIT: Limiter;
}

const MAX_BODY = 1024;
const APNS_TOKEN = /^[0-9a-f]{64,200}$/;
/** FCM registration tokens: case-sensitive, base64url-like with a `:` (about 150–200 characters today). */
const FCM_TOKEN = /^[A-Za-z0-9_:-]{100,512}$/;

const cache = new JwtCache();
const googleCache = new AccessTokenCache();

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
const error = (status: number, code: string, headers: Record<string, string> = {}) =>
	json(status, { error: code }, headers);

export type NotifyRequest =
	| { platform: "apns"; token: string; environment: Environment; kind: "auth_request" }
	| { platform: "fcm"; token: string; environment: "production"; kind: "auth_request" };

/** The request body, or null when it isn't exactly what the contract allows. */
export function parseNotify(value: unknown): NotifyRequest | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const v = value as Record<string, unknown>;
	if (v.kind !== "auth_request" || typeof v.token !== "string") return null;
	if (v.platform === "apns") {
		if (v.environment !== "production" && v.environment !== "sandbox") return null;
		const token = v.token.toLowerCase();
		if (!APNS_TOKEN.test(token)) return null;
		return { platform: "apns", token, environment: v.environment, kind: "auth_request" };
	}
	if (v.platform === "fcm") {
		// FCM has one environment; the server always says "production".
		if (v.environment !== undefined && v.environment !== "production") return null;
		if (!FCM_TOKEN.test(v.token)) return null;
		return { platform: "fcm", token: v.token, environment: "production", kind: "auth_request" };
	}
	return null;
}

export async function handle(
	req: Request,
	env: Env,
	doFetch: typeof fetch = fetch,
): Promise<Response> {
	const url = new URL(req.url);
	if (url.pathname === "/v1/health" && req.method === "GET") return json(200, { ok: true });
	if (url.pathname !== "/v1/notify") return error(404, "not_found");
	if (req.method !== "POST") return error(405, "method_not_allowed", { allow: "POST" });

	const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
	if (!(await env.IP_LIMIT.limit({ key: ip })).success)
		return error(429, "rate_limited", { "retry-after": "60" });

	const declared = Number(req.headers.get("content-length") ?? "0");
	if (declared > MAX_BODY) return error(413, "too_large");
	const text = await req.text();
	if (text.length > MAX_BODY) return error(413, "too_large");
	let body: unknown;
	try {
		body = JSON.parse(text);
	} catch {
		return error(400, "bad_request");
	}
	const notify = parseNotify(body);
	if (!notify) return error(400, "bad_request");

	if (!(await env.TOKEN_LIMIT.limit({ key: notify.token })).success)
		return error(429, "rate_limited", { "retry-after": "60" });

	let outcome: Outcome;
	if (notify.platform === "apns") {
		const config: ApnsConfig = {
			keyP8: env.APNS_KEY_P8,
			keyId: env.APNS_KEY_ID,
			teamId: env.APNS_TEAM_ID,
			topic: env.APNS_TOPIC,
		};
		outcome = await sendAlert(config, cache, notify.environment, notify.token, doFetch);
	} else {
		const account = parseServiceAccount(env.FCM_SERVICE_ACCOUNT);
		outcome = account
			? await sendFcm(account, googleCache, notify.token, doFetch)
			: { kind: "failed", reason: "no FCM service account" };
	}
	switch (outcome.kind) {
		case "sent":
			return json(202, { ok: true });
		case "unregistered":
			return error(410, "unregistered");
		case "throttled":
			return error(429, "rate_limited", { "retry-after": "60" });
		case "failed":
			// The reason is Apple's (or the network's); never the token.
			console.warn(`${notify.platform} failed: ${outcome.reason}`);
			return error(502, "upstream");
	}
}

export default {
	fetch(req, env) {
		return handle(req, env as Env);
	},
} satisfies ExportedHandler;
