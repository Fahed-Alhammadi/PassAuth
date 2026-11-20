/**
 * PassAuth push relay. Self-hosted PassAuth servers can't hold the app publisher's Apple push key, so they ask this
 * relay to wake one device up: `POST /v1/notify {platform, token, environment, kind}`. The relay signs with the key and
 * sends Apple a fixed alert ("Sign-in request … Open PassAuth to review.").
 *
 * It stores nothing and never sees an account, an email or a server's data: only the device's push token and when to
 * send. Limits: a token gets at most a few alerts a minute, an address a few hundred (Cloudflare rate limiting).
 *
 * Answers (the server's contract): 202 sent · 410 unregistered (the server forgets the token) · 400 bad_request ·
 * 413 too_large · 429 rate_limited · 502 upstream.
 */
import { type ApnsConfig, type Environment, JwtCache, sendAlert } from "./apns";

interface Limiter {
	limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
	APNS_KEY_P8: string;
	APNS_KEY_ID: string;
	APNS_TEAM_ID: string;
	APNS_TOPIC: string;
	/** Per device token. */
	TOKEN_LIMIT: Limiter;
	/** Per calling address (a PassAuth server). */
	IP_LIMIT: Limiter;
}

const MAX_BODY = 1024;
const TOKEN = /^[0-9a-f]{64,200}$/;

const cache = new JwtCache();

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
	Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
const error = (status: number, code: string, headers: Record<string, string> = {}) =>
	json(status, { error: code }, headers);

export interface NotifyRequest {
	platform: "apns";
	token: string;
	environment: Environment;
	kind: "auth_request";
}

/** The request body, or null when it isn't exactly what the contract allows. */
export function parseNotify(value: unknown): NotifyRequest | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const v = value as Record<string, unknown>;
	if (v.platform !== "apns" || v.kind !== "auth_request") return null;
	if (v.environment !== "production" && v.environment !== "sandbox") return null;
	if (typeof v.token !== "string") return null;
	const token = v.token.toLowerCase();
	if (!TOKEN.test(token)) return null;
	return { platform: "apns", token, environment: v.environment, kind: "auth_request" };
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

	const config: ApnsConfig = {
		keyP8: env.APNS_KEY_P8,
		keyId: env.APNS_KEY_ID,
		teamId: env.APNS_TEAM_ID,
		topic: env.APNS_TOPIC,
	};
	const outcome = await sendAlert(config, cache, notify.environment, notify.token, doFetch);
	switch (outcome.kind) {
		case "sent":
			return json(202, { ok: true });
		case "unregistered":
			return error(410, "unregistered");
		case "throttled":
			return error(429, "rate_limited", { "retry-after": "60" });
		case "failed":
			// The reason is Apple's (or the network's); never the token.
			console.warn(`APNs failed: ${outcome.reason}`);
			return error(502, "upstream");
	}
}

export default {
	fetch(req, env) {
		return handle(req, env as Env);
	},
} satisfies ExportedHandler;
