// Android (FCM HTTP v1) through the relay, with Google faked.
import { describe, expect, it } from "vite-plus/test";
import {
	AccessTokenCache,
	fcmMessage,
	makeAssertion,
	type ServiceAccount,
	sendFcm,
} from "../src/fcm.ts";
import { type Env, handle, parseNotify } from "../src/index.ts";

const FCM = `dGVzdC1kZXZpY2U:APA91b${"Xy_z-9".repeat(25)}`;

async function account(): Promise<{ sa: ServiceAccount; publicKey: CryptoKey }> {
	const pair = (await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const der = new Uint8Array(
		(await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer,
	);
	const b64 = btoa(String.fromCharCode(...der));
	return {
		sa: {
			project_id: "passauth-test",
			client_email: "sender@passauth-test.iam.gserviceaccount.com",
			private_key: `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`,
			token_uri: "https://oauth2.googleapis.com/token",
		},
		publicKey: pair.publicKey,
	};
}

type Call = { url: string; init: RequestInit };
/** Google: the token endpoint answers `oauth`, the send endpoint answers `sends` in order. */
function google(sends: Array<{ status: number; body?: unknown }>, oauth = { status: 200 }) {
	const calls: Call[] = [];
	let sent = 0;
	let issued = 0;
	const f = (async (url: string, init: RequestInit) => {
		calls.push({ url, init });
		if (url.includes("oauth2")) {
			issued++;
			return Response.json(
				oauth.status === 200
					? { access_token: `ya29.token${issued}`, expires_in: 3599 }
					: { error: "invalid_grant" },
				{ status: oauth.status },
			);
		}
		const a = sends[Math.min(sent++, sends.length - 1)]!;
		return new Response(a.body ? JSON.stringify(a.body) : "{}", { status: a.status });
	}) as unknown as typeof fetch;
	return { f, calls, sendCalls: () => calls.filter((c) => c.url.includes("fcm.googleapis.com")) };
}

const allow = { limit: async () => ({ success: true }) };
async function env(over: Partial<Env> = {}): Promise<Env> {
	const { sa } = await account();
	return {
		APNS_KEY_P8: "unused",
		APNS_KEY_ID: "K",
		APNS_TEAM_ID: "T",
		APNS_TOPIC: "io.passauth.app",
		FCM_SERVICE_ACCOUNT: JSON.stringify(sa),
		TOKEN_LIMIT: allow,
		IP_LIMIT: allow,
		...over,
	};
}
const good = { platform: "fcm", token: FCM, environment: "production", kind: "auth_request" };
const notify = (body: unknown) =>
	new Request("https://relay.test/v1/notify", { method: "POST", body: JSON.stringify(body) });
const fcmError = (status: string, message = "", errorCode?: string) => ({
	error: { status, message, details: errorCode ? [{ errorCode }] : [] },
});

describe("parseNotify (fcm)", () => {
	it("keeps the token's case and allows a missing environment", () => {
		expect(parseNotify(good)).toEqual(good);
		const { environment: _, ...noEnv } = good;
		expect(parseNotify(noEnv)).toEqual(good);
	});
	it("refuses other environments and malformed tokens", () => {
		for (const bad of [
			{ ...good, environment: "sandbox" },
			{ ...good, token: "short:token" },
			{ ...good, token: `${FCM}!` },
			{ ...good, token: "a".repeat(513) },
		])
			expect(parseNotify(bad)).toBe(null);
	});
});

describe("POST /v1/notify (fcm)", () => {
	it("signs in to Google and sends a data-only message: 202", async () => {
		const g = google([{ status: 200, body: { name: "projects/x/messages/1" } }]);
		const e = await env();
		const res = await handle(notify(good), e, g.f);
		expect(res.status).toBe(202);
		const [send] = g.sendCalls();
		expect(send!.url).toMatch(
			/^https:\/\/fcm\.googleapis\.com\/v1\/projects\/passauth-test\/messages:send$/,
		);
		expect((send!.init.headers as Record<string, string>).authorization).toMatch(
			/^Bearer ya29\.token\d+$/,
		);
		const body = JSON.parse(send!.init.body as string);
		expect(body).toEqual(fcmMessage(FCM));
		// No text and no account data travel through Google: the app shows the fixed notice.
		expect(body.message.notification).toBeUndefined();
		expect(body.message.data).toEqual({ kind: "auth_request" });
		expect(body.message.android).toEqual({
			priority: "HIGH",
			ttl: "900s",
			collapse_key: "passauth-signin",
		});
	});

	it("dead tokens are 410", async () => {
		for (const answer of [
			{
				status: 404,
				body: fcmError("NOT_FOUND", "Requested entity was not found.", "UNREGISTERED"),
			},
			{
				status: 403,
				body: fcmError("PERMISSION_DENIED", "SenderId mismatch", "SENDER_ID_MISMATCH"),
			},
			{
				status: 400,
				body: fcmError(
					"INVALID_ARGUMENT",
					"The registration token is not a valid FCM registration token",
					"INVALID_ARGUMENT",
				),
			},
		]) {
			const res = await handle(notify(good), await env(), google([answer]).f);
			expect(res.status).toBe(410);
		}
	});

	it("another invalid argument is not blamed on the token", async () => {
		const res = await handle(
			notify(good),
			await env(),
			google([
				{
					status: 400,
					body: fcmError("INVALID_ARGUMENT", "Invalid value at 'message.android.ttl'"),
				},
			]).f,
		);
		expect(res.status).toBe(502);
	});

	it("a refused access token is renewed and the message sent once more", async () => {
		const g = google([{ status: 401, body: fcmError("UNAUTHENTICATED") }, { status: 200 }]);
		expect((await handle(notify(good), await env(), g.f)).status).toBe(202);
		expect(g.sendCalls()).toHaveLength(2);
	});

	it("Google busy → 429; no account, refused sign-in or outage → 502", async () => {
		expect(
			(
				await handle(
					notify(good),
					await env(),
					google([{ status: 429, body: fcmError("RESOURCE_EXHAUSTED") }]).f,
				)
			).status,
		).toBe(429);
		expect((await handle(notify(good), await env(), google([{ status: 503 }]).f)).status).toBe(502);
		expect(
			(
				await handle(
					notify(good),
					await env({ FCM_SERVICE_ACCOUNT: undefined }),
					google([{ status: 200 }]).f,
				)
			).status,
		).toBe(502);
		expect(
			(
				await handle(
					notify(good),
					await env({ FCM_SERVICE_ACCOUNT: "{not json" }),
					google([{ status: 200 }]).f,
				)
			).status,
		).toBe(502);
	});
});

describe("Google sign-in", () => {
	it("the assertion is an RS256 JWT for the messaging scope", async () => {
		const { sa, publicKey } = await account();
		const jwt = await makeAssertion(sa, 1_700_000_000_000);
		const [h, c, s] = jwt.split(".") as [string, string, string];
		const dec = (x: string) => JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/")));
		expect(dec(h)).toEqual({ alg: "RS256", typ: "JWT" });
		expect(dec(c)).toEqual({
			iss: sa.client_email,
			scope: "https://www.googleapis.com/auth/firebase.messaging",
			aud: "https://oauth2.googleapis.com/token",
			iat: 1_700_000_000,
			exp: 1_700_003_600,
		});
		const sig = Uint8Array.from(
			atob(
				s
					.replace(/-/g, "+")
					.replace(/_/g, "/")
					.padEnd(Math.ceil(s.length / 4) * 4, "="),
			),
			(ch) => ch.charCodeAt(0),
		);
		expect(
			await crypto.subtle.verify(
				"RSASSA-PKCS1-v1_5",
				publicKey,
				sig,
				new TextEncoder().encode(`${h}.${c}`),
			),
		).toBe(true);
	});

	it("the access token is reused until 5 minutes before it expires", async () => {
		const { sa } = await account();
		let now = 1_700_000_000_000;
		const cache = new AccessTokenCache(() => now);
		const g = google([{ status: 200 }]);
		await sendFcm(sa, cache, FCM, g.f);
		now += 54 * 60_000;
		await sendFcm(sa, cache, FCM, g.f);
		expect(g.calls.filter((c) => c.url.includes("oauth2"))).toHaveLength(1);
		now += 2 * 60_000;
		await sendFcm(sa, cache, FCM, g.f);
		expect(g.calls.filter((c) => c.url.includes("oauth2"))).toHaveLength(2);
	});
});
