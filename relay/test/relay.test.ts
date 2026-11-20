// The relay's contract with PassAuth servers (POST /v1/notify) and its APNs requests, with Apple faked.
import { describe, expect, it } from "vite-plus/test";
import { ALERT, type ApnsConfig, JwtCache, makeJwt, payload, sendAlert } from "../src/apns.ts";
import { type Env, handle, parseNotify } from "../src/index.ts";

const TOKEN = "a1".repeat(32);

async function testKey(): Promise<{ pem: string; publicKey: CryptoKey }> {
	const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const der = new Uint8Array(
		(await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer,
	);
	const b64 = btoa(String.fromCharCode(...der));
	return {
		pem: `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`,
		publicKey: pair.publicKey,
	};
}

const allow = { limit: async () => ({ success: true }) };
const deny = { limit: async () => ({ success: false }) };

async function makeEnv(over: Partial<Env> = {}): Promise<Env> {
	const { pem } = await testKey();
	return {
		APNS_KEY_P8: pem,
		APNS_KEY_ID: "KEYID12345",
		APNS_TEAM_ID: "TEAM123456",
		APNS_TOPIC: "io.passauth.app",
		TOKEN_LIMIT: allow,
		IP_LIMIT: allow,
		...over,
	};
}

type Call = { url: string; init: RequestInit };
function apple(...answers: Array<{ status: number; reason?: string }>) {
	const calls: Call[] = [];
	const f = (async (url: string, init: RequestInit) => {
		calls.push({ url, init });
		const a = answers[Math.min(calls.length - 1, answers.length - 1)]!;
		return new Response(a.reason ? JSON.stringify({ reason: a.reason }) : "", { status: a.status });
	}) as unknown as typeof fetch;
	return { f, calls };
}

const notify = (body: unknown, init: RequestInit = {}) =>
	new Request("https://relay.test/v1/notify", {
		method: "POST",
		body: typeof body === "string" ? body : JSON.stringify(body),
		...init,
	});
const good = { platform: "apns", token: TOKEN, environment: "production", kind: "auth_request" };

describe("parseNotify", () => {
	it("accepts exactly the contract and lower-cases the token", () => {
		expect(parseNotify({ ...good, token: TOKEN.toUpperCase() })).toEqual({ ...good, token: TOKEN });
		expect(parseNotify({ ...good, environment: "sandbox" })?.environment).toBe("sandbox");
	});
	it("refuses anything else", () => {
		for (const bad of [
			null,
			[],
			"x",
			{ ...good, platform: "fcm" },
			{ ...good, kind: "other" },
			{ ...good, environment: "dev" },
			{ ...good, token: "abc" },
			{ ...good, token: "zz".repeat(32) },
			{ ...good, token: "a".repeat(201) },
			{ ...good, token: 5 },
		])
			expect(parseNotify(bad)).toBe(null);
	});
});

describe("POST /v1/notify", () => {
	it("sends the fixed alert to the production host and answers 202", async () => {
		const { f, calls } = apple({ status: 200 });
		const res = await handle(notify(good), await makeEnv(), f);
		expect(res.status).toBe(202);
		expect(await res.json()).toEqual({ ok: true });
		expect(calls).toHaveLength(1);
		const { url, init } = calls[0]!;
		expect(url).toBe(`https://api.push.apple.com/3/device/${TOKEN}`);
		const h = init.headers as Record<string, string>;
		expect(h["apns-topic"]).toBe("io.passauth.app");
		expect(h["apns-push-type"]).toBe("alert");
		expect(h["apns-priority"]).toBe("10");
		expect(h["apns-collapse-id"]).toBe("passauth-signin");
		expect(h.authorization).toMatch(/^bearer [\w-]+\.[\w-]+\.[\w-]+$/);
		// No account data in what Apple shows.
		expect(JSON.parse(init.body as string)).toEqual(payload());
		expect(payload().aps.alert).toEqual(ALERT);
	});

	it("uses the sandbox host for sandbox tokens", async () => {
		const { f, calls } = apple({ status: 200 });
		await handle(notify({ ...good, environment: "sandbox" }), await makeEnv(), f);
		expect(calls[0]!.url.startsWith("https://api.sandbox.push.apple.com/3/device/")).toBe(true);
	});

	it("410 unregistered for dead tokens", async () => {
		for (const answer of [
			{ status: 410, reason: "Unregistered" },
			{ status: 400, reason: "BadDeviceToken" },
			{ status: 400, reason: "DeviceTokenNotForTopic" },
		]) {
			const { f } = apple(answer);
			const res = await handle(notify(good), await makeEnv(), f);
			expect(res.status).toBe(410);
			expect(await res.json()).toEqual({ error: "unregistered" });
		}
	});

	it("a refused JWT is made again and the alert sent once more", async () => {
		const { f, calls } = apple({ status: 403, reason: "ExpiredProviderToken" }, { status: 200 });
		expect((await handle(notify(good), await makeEnv(), f)).status).toBe(202);
		expect(calls).toHaveLength(2);
	});

	it("Apple busy → 429, other failures → 502", async () => {
		expect(
			(
				await handle(
					notify(good),
					await makeEnv(),
					apple({ status: 429, reason: "TooManyRequests" }).f,
				)
			).status,
		).toBe(429);
		expect(
			(
				await handle(
					notify(good),
					await makeEnv(),
					apple({ status: 500, reason: "InternalServerError" }).f,
				)
			).status,
		).toBe(502);
		const broken = (async () => {
			throw new Error("down");
		}) as unknown as typeof fetch;
		expect((await handle(notify(good), await makeEnv(), broken)).status).toBe(502);
	});

	it("bad bodies are 400, big ones 413, and nothing reaches Apple", async () => {
		const { f, calls } = apple({ status: 200 });
		const env = await makeEnv();
		expect((await handle(notify("{not json"), env, f)).status).toBe(400);
		expect((await handle(notify({ ...good, token: "12" }), env, f)).status).toBe(400);
		expect((await handle(notify("x".repeat(2000)), env, f)).status).toBe(413);
		expect(calls).toHaveLength(0);
	});

	it("rate limits per token and per address", async () => {
		const { f, calls } = apple({ status: 200 });
		const byToken = await handle(notify(good), await makeEnv({ TOKEN_LIMIT: deny }), f);
		expect(byToken.status).toBe(429);
		expect(byToken.headers.get("retry-after")).toBe("60");
		expect((await handle(notify(good), await makeEnv({ IP_LIMIT: deny }), f)).status).toBe(429);
		expect(calls).toHaveLength(0);
	});

	it("other paths and methods", async () => {
		const env = await makeEnv();
		expect((await handle(new Request("https://relay.test/v1/health"), env)).status).toBe(200);
		expect((await handle(new Request("https://relay.test/"), env)).status).toBe(404);
		expect((await handle(new Request("https://relay.test/v1/notify"), env)).status).toBe(405);
	});
});

describe("provider token", () => {
	it("is an ES256 JWT Apple can verify with the key's public half", async () => {
		const { pem, publicKey } = await testKey();
		const config: ApnsConfig = {
			keyP8: pem,
			keyId: "KEYID12345",
			teamId: "TEAM123456",
			topic: "io.passauth.app",
		};
		const jwt = await makeJwt(config, 1_700_000_000_000);
		const [h, c, s] = jwt.split(".") as [string, string, string];
		const dec = (x: string) => JSON.parse(atob(x.replace(/-/g, "+").replace(/_/g, "/")));
		expect(dec(h)).toEqual({ alg: "ES256", kid: "KEYID12345" });
		expect(dec(c)).toEqual({ iss: "TEAM123456", iat: 1_700_000_000 });
		const sig = Uint8Array.from(
			atob(
				s
					.replace(/-/g, "+")
					.replace(/_/g, "/")
					.padEnd(Math.ceil(s.length / 4) * 4, "="),
			),
			(ch) => ch.charCodeAt(0),
		);
		expect(sig.length).toBe(64);
		expect(
			await crypto.subtle.verify(
				{ name: "ECDSA", hash: "SHA-256" },
				publicKey,
				sig,
				new TextEncoder().encode(`${h}.${c}`),
			),
		).toBe(true);
	});

	it("is reused for 30 minutes, then renewed", async () => {
		const { pem } = await testKey();
		const config: ApnsConfig = { keyP8: pem, keyId: "K", teamId: "T", topic: "io.passauth.app" };
		let now = 1_700_000_000_000;
		const cache = new JwtCache(() => now);
		const first = await cache.get(config);
		now += 29 * 60_000;
		expect(await cache.get(config)).toBe(first);
		now += 2 * 60_000;
		expect(await cache.get(config)).not.toBe(first);
	});

	it("sendAlert sets the expiry 15 minutes ahead", async () => {
		const { pem } = await testKey();
		const { f, calls } = apple({ status: 200 });
		await sendAlert(
			{ keyP8: pem, keyId: "K", teamId: "T", topic: "io.passauth.app" },
			new JwtCache(),
			"production",
			TOKEN,
			f,
			1_700_000_000_000,
		);
		expect((calls[0]!.init.headers as Record<string, string>)["apns-expiration"]).toBe(
			String(1_700_000_000 + 900),
		);
	});
});
