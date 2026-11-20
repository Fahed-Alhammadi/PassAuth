/**
 * Firebase Cloud Messaging (FCM HTTP v1) for the Android app. The relay signs in to Google with the Firebase
 * service account (an RS256 JWT exchanged for an OAuth access token, reused until shortly before it expires) and
 * sends one data-only, high-priority message: `{kind: "auth_request"}`. The app itself shows the fixed notice
 * ("Sign-in request … Open PassAuth to review."), so no text and no account data travel through Google.
 */
import type { Outcome } from "./apns";
import { EXPIRY_SECONDS } from "./apns";

export interface ServiceAccount {
	project_id: string;
	client_email: string;
	private_key: string;
	token_uri?: string;
}

const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
/** Renew this long before Google's expiry. */
const MARGIN_MS = 5 * 60_000;

/** The service account from the secret's JSON, or null when it isn't one. */
export function parseServiceAccount(json: string | undefined): ServiceAccount | null {
	if (!json) return null;
	try {
		const v = JSON.parse(json) as Partial<ServiceAccount>;
		if (
			typeof v.project_id === "string" &&
			typeof v.client_email === "string" &&
			typeof v.private_key === "string"
		)
			return {
				project_id: v.project_id,
				client_email: v.client_email,
				private_key: v.private_key,
				token_uri: typeof v.token_uri === "string" ? v.token_uri : undefined,
			};
	} catch {}
	return null;
}

const b64url = (bytes: ArrayBuffer | Uint8Array) => {
	const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let s = "";
	for (const b of u8) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const b64urlText = (text: string) => b64url(new TextEncoder().encode(text));

async function importRsaKey(pem: string): Promise<CryptoKey> {
	const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
	const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey(
		"pkcs8",
		der,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"],
	);
}

/** The signed assertion Google exchanges for an access token (RFC 7523). */
export async function makeAssertion(sa: ServiceAccount, nowMs: number): Promise<string> {
	const iat = Math.floor(nowMs / 1000);
	const header = b64urlText(JSON.stringify({ alg: "RS256", typ: "JWT" }));
	const claims = b64urlText(
		JSON.stringify({
			iss: sa.client_email,
			scope: SCOPE,
			aud: sa.token_uri ?? DEFAULT_TOKEN_URI,
			iat,
			exp: iat + 3600,
		}),
	);
	const input = `${header}.${claims}`;
	const sig = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		await importRsaKey(sa.private_key),
		new TextEncoder().encode(input),
	);
	return `${input}.${b64url(sig)}`;
}

/** One access token per isolate, renewed 5 minutes before it expires or when Google refuses it. */
export class AccessTokenCache {
	private value: { token: string; until: number; account: string } | null = null;
	constructor(private readonly now: () => number = Date.now) {}

	async get(sa: ServiceAccount, doFetch: typeof fetch): Promise<string | null> {
		const t = this.now();
		if (this.value && this.value.account === sa.client_email && t < this.value.until)
			return this.value.token;
		const res = await doFetch(sa.token_uri ?? DEFAULT_TOKEN_URI, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
				assertion: await makeAssertion(sa, t),
			}).toString(),
		});
		if (!res.ok) return null;
		const j = await res
			.json<{ access_token?: string; expires_in?: number }>()
			.catch(() => ({}) as { access_token?: string; expires_in?: number });
		if (!j.access_token) return null;
		this.value = {
			token: j.access_token,
			until: t + (j.expires_in ?? 3600) * 1000 - MARGIN_MS,
			account: sa.client_email,
		};
		return j.access_token;
	}

	clear() {
		this.value = null;
	}
}

/** The message for one device: data only, so the app shows its own fixed notice. */
export function fcmMessage(token: string) {
	return {
		message: {
			token,
			data: { kind: "auth_request" },
			android: {
				priority: "HIGH",
				ttl: `${EXPIRY_SECONDS}s`,
				collapse_key: "passauth-signin",
			},
		},
	};
}

interface FcmError {
	error?: { status?: string; message?: string; details?: Array<{ errorCode?: string }> };
}

/** Send the sign-in request to one Android device. Never throws: every failure is an Outcome. */
export async function sendFcm(
	sa: ServiceAccount,
	cache: AccessTokenCache,
	token: string,
	doFetch: typeof fetch = fetch,
): Promise<Outcome> {
	const url = `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`;
	const body = JSON.stringify(fcmMessage(token));
	for (let attempt = 0; attempt < 2; attempt++) {
		let res: Response;
		try {
			const access = await cache.get(sa, doFetch);
			if (!access) return { kind: "failed", reason: "google sign-in refused" };
			res = await doFetch(url, {
				method: "POST",
				headers: { authorization: `Bearer ${access}`, "content-type": "application/json" },
				body,
			});
		} catch (e) {
			return { kind: "failed", reason: `network: ${e instanceof Error ? e.message : String(e)}` };
		}
		if (res.status === 200) return { kind: "sent" };
		const j = await res.json<FcmError>().catch(() => ({}) as FcmError);
		const codes = new Set(
			[j.error?.status, ...(j.error?.details ?? []).map((d) => d.errorCode)].filter(Boolean),
		);
		// The token is gone (app removed, data cleared), belongs to another Firebase project, or isn't one:
		// our message itself is fixed, so an invalid argument naming the token means the token.
		if (
			res.status === 404 ||
			codes.has("UNREGISTERED") ||
			codes.has("SENDER_ID_MISMATCH") ||
			(res.status === 400 && /registration token/i.test(j.error?.message ?? ""))
		)
			return { kind: "unregistered" };
		if (res.status === 401 && attempt === 0) {
			cache.clear();
			continue;
		}
		if (res.status === 429) return { kind: "throttled" };
		return { kind: "failed", reason: `${res.status} ${[...codes].join(",")}`.trim() };
	}
	return { kind: "failed", reason: "google access token refused" };
}
