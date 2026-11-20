/**
 * Apple Push Notification service (APNs): token-based authentication (an ES256 JWT signed with the team's .p8 key,
 * reused for 30 minutes as Apple asks: not more often than every 20 minutes, not longer than 60) and one alert per
 * call. The alert's text is fixed and carries no account data: the app finds the request itself once it is opened.
 */

export const ALERT = {
	title: "Sign-in request",
	body: "Someone wants to sign in to your PassAuth account on a new device. Open PassAuth to review.",
} as const;

/** How long Apple keeps trying to deliver: the sign-in request itself lives 15 minutes. */
export const EXPIRY_SECONDS = 15 * 60;
const JWT_LIFETIME_MS = 30 * 60_000;

export interface ApnsConfig {
	/** The .p8 file's contents (PKCS #8 PEM, P-256). */
	keyP8: string;
	keyId: string;
	teamId: string;
	/** The app's bundle id. */
	topic: string;
}

export type Environment = "production" | "sandbox";

/** What the relay tells the server: sent, the token is dead (forget it), Apple is busy, or another failure. */
export type Outcome =
	| { kind: "sent" }
	| { kind: "unregistered" }
	| { kind: "throttled" }
	| { kind: "failed"; reason: string };

const HOSTS: Record<Environment, string> = {
	production: "https://api.push.apple.com",
	sandbox: "https://api.sandbox.push.apple.com",
};

/** Reasons that mean this token will never work again for this app. */
const DEAD = new Set(["BadDeviceToken", "DeviceTokenNotForTopic", "Unregistered"]);
/** Reasons that mean our JWT was refused: make a new one and try once more. */
const STALE_JWT = new Set(["ExpiredProviderToken", "InvalidProviderToken"]);

const b64url = (bytes: ArrayBuffer | Uint8Array) => {
	const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
	let s = "";
	for (const b of u8) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const b64urlText = (text: string) => b64url(new TextEncoder().encode(text));

async function importKey(pem: string): Promise<CryptoKey> {
	const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
	const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, [
		"sign",
	]);
}

/** The provider token (JWT): `{alg: ES256, kid}` / `{iss: team, iat}`, signed raw r‖s as JWS wants. */
export async function makeJwt(config: ApnsConfig, nowMs: number): Promise<string> {
	const header = b64urlText(JSON.stringify({ alg: "ES256", kid: config.keyId }));
	const claims = b64urlText(JSON.stringify({ iss: config.teamId, iat: Math.floor(nowMs / 1000) }));
	const input = `${header}.${claims}`;
	const key = await importKey(config.keyP8);
	const sig = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		key,
		new TextEncoder().encode(input),
	);
	return `${input}.${b64url(sig)}`;
}

/** One JWT per isolate, renewed after 30 minutes or when Apple refuses it. */
export class JwtCache {
	private value: { jwt: string; at: number; keyId: string } | null = null;
	constructor(private readonly now: () => number = Date.now) {}

	async get(config: ApnsConfig): Promise<string> {
		const t = this.now();
		if (
			this.value &&
			this.value.keyId === config.keyId &&
			t - this.value.at < JWT_LIFETIME_MS &&
			t >= this.value.at
		)
			return this.value.jwt;
		const jwt = await makeJwt(config, t);
		this.value = { jwt, at: t, keyId: config.keyId };
		return jwt;
	}

	clear() {
		this.value = null;
	}
}

export function payload() {
	return {
		aps: { alert: { ...ALERT }, sound: "default", "thread-id": "signin" },
		passauth: { kind: "auth_request" },
	};
}

/** Send the sign-in request alert to one device. Never throws: every failure is an Outcome. */
export async function sendAlert(
	config: ApnsConfig,
	cache: JwtCache,
	environment: Environment,
	token: string,
	doFetch: typeof fetch = fetch,
	nowMs: number = Date.now(),
): Promise<Outcome> {
	const body = JSON.stringify(payload());
	for (let attempt = 0; attempt < 2; attempt++) {
		let res: Response;
		try {
			res = await doFetch(`${HOSTS[environment]}/3/device/${token}`, {
				method: "POST",
				headers: {
					authorization: `bearer ${await cache.get(config)}`,
					"apns-topic": config.topic,
					"apns-push-type": "alert",
					"apns-priority": "10",
					"apns-expiration": String(Math.floor(nowMs / 1000) + EXPIRY_SECONDS),
					"apns-collapse-id": "passauth-signin",
					"content-type": "application/json",
				},
				body,
			});
		} catch (e) {
			return { kind: "failed", reason: `network: ${e instanceof Error ? e.message : String(e)}` };
		}
		if (res.status === 200) return { kind: "sent" };
		const reason = await res
			.json<{ reason?: string }>()
			.then((j) => j.reason ?? "")
			.catch(() => "");
		if (res.status === 410 || DEAD.has(reason)) return { kind: "unregistered" };
		if (res.status === 403 && STALE_JWT.has(reason) && attempt === 0) {
			cache.clear();
			continue;
		}
		if (res.status === 429) return { kind: "throttled" };
		return { kind: "failed", reason: `${res.status} ${reason}`.trim() };
	}
	return { kind: "failed", reason: "provider token refused" };
}
