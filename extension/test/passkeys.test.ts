// Cryptographic tests for src/background/passkeys.ts (the software WebAuthn authenticator).

import { expect, test } from "vitest";
import {
  b64uDecode,
  b64uEncode,
  createPasskey,
  effectiveRpId,
  errorReply,
  excludedPasskeyExists,
  getAssertion,
  matchingPasskeys,
  PASSAUTH_AAGUID,
  PasskeyError,
  PasskeyFallback,
  rawSignatureToDer,
  userVerification,
} from "../src/background/passkeys";
import type { CreateRequest, GetRequest, Passkey } from "../src/shared/passkey-types";
import { expectReject, expectThrow, fromB64u, toB64u } from "./helpers";

// ------------------------------------------------------------------ helpers (independent of the code under test)

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const sha256 = async (b: Uint8Array) => new Uint8Array(await subtle.digest("SHA-256", b as Uint8Array<ArrayBuffer>));
const concat = (...p: (Uint8Array | number[])[]) => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const bytes = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

/** Minimal CBOR decoder: uint, negint, bytes, text, array, map (→ Map), true/false/null. */
function cborDecode(data: Uint8Array): any {
  let pos = 0;
  const readLen = (info: number) => {
    if (info < 24) return info;
    const n = ({ 24: 1, 25: 2, 26: 4 } as Record<number, number>)[info] ?? 0;
    expect(n, `unsupported CBOR length info ${info}`).toBeTruthy();
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + data[pos++]!;
    return v;
  };
  const item = (): any => {
    const ib = data[pos++]!;
    const major = ib >> 5;
    const info = ib & 31;
    switch (major) {
      case 0:
        return readLen(info);
      case 1:
        return -1 - readLen(info);
      case 2: {
        const n = readLen(info);
        const b = data.slice(pos, pos + n);
        pos += n;
        return b;
      }
      case 3: {
        const n = readLen(info);
        const s = new TextDecoder().decode(data.slice(pos, pos + n));
        pos += n;
        return s;
      }
      case 4: {
        const n = readLen(info);
        return Array.from({ length: n }, item);
      }
      case 5: {
        const n = readLen(info);
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = item();
          m.set(k, item());
        }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
    }
    throw new Error(`unsupported CBOR initial byte 0x${ib.toString(16)}`);
  };
  const v = item();
  expect(pos, "trailing bytes after CBOR item").toBe(data.length);
  return v;
}

/** Strict DER ECDSA-Sig-Value → raw r||s (32 bytes each). */
function derToRaw(der: Uint8Array) {
  let p = 0;
  expect(der[p++]).toBe(0x30);
  expect(der[p++], "SEQUENCE length").toBe(der.length - 2);
  const int = () => {
    expect(der[p++]).toBe(0x02);
    const len = der[p++]!;
    let v = der.slice(p, p + len);
    p += len;
    expect(len >= 1 && len <= 33).toBe(true);
    expect(v[0]! & 0x80, "INTEGER must be positive").toBe(0);
    if (len > 1) expect(!(v[0] === 0 && !(v[1]! & 0x80)), "non-minimal INTEGER").toBe(true);
    if (v.length === 33) v = v.slice(1);
    return concat(new Uint8Array(32 - v.length), v);
  };
  const r = int();
  const s = int();
  expect(p).toBe(der.length);
  return concat(r, s);
}

function parseAuthData(ad: Uint8Array) {
  const out: { rpIdHash: Uint8Array; flags: number; signCount: number; aaguid?: Uint8Array; credentialId?: Uint8Array; coseKeyBytes?: Uint8Array } = {
    rpIdHash: ad.slice(0, 32),
    flags: ad[32]!,
    signCount: new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0),
  };
  if (out.flags & 0x40) {
    out.aaguid = ad.slice(37, 53);
    const idLen = (ad[53]! << 8) | ad[54]!;
    out.credentialId = ad.slice(55, 55 + idLen);
    out.coseKeyBytes = ad.slice(55 + idLen);
  } else {
    expect(ad.length).toBe(37);
  }
  return out;
}

const ORIGIN = "https://login.example.com";
const createReq = (): CreateRequest => ({
  rp: { id: "example.com", name: "Example" },
  user: { id: toB64u(enc.encode("user-1234")), name: "alice@example.com", displayName: "Alice" },
  challenge: toB64u(crypto.getRandomValues(new Uint8Array(32))),
  pubKeyCredParams: [
    { type: "public-key", alg: -8 },
    { type: "public-key", alg: -7 },
    { type: "public-key", alg: -257 },
  ],
  authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  attestation: "direct",
  extensions: { credProps: true },
});

// ------------------------------------------------------------------ tests

let created: Awaited<ReturnType<typeof createPasskey>>; // shared between create and get tests
let createdReq: CreateRequest;

test("createPasskey: attestationObject, authData, COSE key, clientDataJSON", async () => {
  createdReq = createReq();
  created = await createPasskey(createdReq, ORIGIN);
  const { passkey, response } = created;
  const r = response.response;

  expect(response.type).toBe("public-key");
  expect(response.authenticatorAttachment).toBe("platform");
  expect(response.id).toBe(response.rawId);
  expect(fromB64u(response.rawId).length).toBe(16);
  expect(response.clientExtensionResults).toStrictEqual({ credProps: { rk: true } });
  expect(r.transports).toStrictEqual(["internal", "hybrid"]);
  expect(r.publicKeyAlgorithm).toBe(-7);

  // clientDataJSON: byte-exact.
  const cdj = new TextDecoder().decode(fromB64u(r.clientDataJSON));
  expect(cdj).toBe(`{"type":"webauthn.create","challenge":"${createdReq.challenge}","origin":"${ORIGIN}","crossOrigin":false}`);

  // attestationObject: {"fmt":"none","attStmt":{},"authData":bytes} in canonical order.
  const attObjBytes = fromB64u(r.attestationObject);
  const att = cborDecode(attObjBytes);
  expect([...att.keys()]).toStrictEqual(["fmt", "attStmt", "authData"]);
  expect(att.get("fmt")).toBe("none");
  expect(att.get("attStmt") instanceof Map && att.get("attStmt").size === 0).toBe(true);
  const authData = att.get("authData");
  expect(authData).toStrictEqual(fromB64u(r.authenticatorData));

  const ad = parseAuthData(authData);
  expect(ad.rpIdHash).toStrictEqual(await sha256(enc.encode("example.com")));
  expect(ad.flags, "flags UP|UV|BE|BS|AT").toBe(0x01 | 0x04 | 0x08 | 0x10 | 0x40);
  expect(ad.signCount).toBe(0);
  expect(ad.aaguid).toStrictEqual(new Uint8Array(PASSAUTH_AAGUID));
  expect(toB64u(ad.credentialId!)).toBe(response.id);

  // COSE_Key {1:2, 3:-7, -1:1, -2:x, -3:y}, canonical order, and equal to the SPKI key.
  const cose = cborDecode(ad.coseKeyBytes!);
  expect([...cose.keys()]).toStrictEqual([1, 3, -1, -2, -3]);
  expect(cose.get(1)).toBe(2);
  expect(cose.get(3)).toBe(-7);
  expect(cose.get(-1)).toBe(1);
  expect(cose.get(-2).length).toBe(32);
  expect(cose.get(-3).length).toBe(32);
  const spkiKey = await subtle.importKey("spki", bytes(fromB64u(r.publicKey)), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const spkiRaw = new Uint8Array(await subtle.exportKey("raw", spkiKey));
  expect(spkiRaw).toStrictEqual(concat([0x04], cose.get(-2), cose.get(-3)));

  // Stored passkey.
  expect(passkey.credential_id).toBe(response.id);
  expect(passkey.rp_id).toBe("example.com");
  expect(passkey.rp_name).toBe("Example");
  expect(passkey.user_handle).toBe(createdReq.user.id);
  expect(passkey.user_name).toBe("alice@example.com");
  expect(passkey.user_display_name).toBe("Alice");
  expect(passkey.algorithm).toBe(-7);
  expect(passkey.counter).toBe(0);
  expect(passkey.discoverable).toBe(true);
  expect(Math.abs(passkey.created_at - Date.now() / 1000) < 60).toBe(true);
  await subtle.importKey("pkcs8", bytes(fromB64u(passkey.private_key)), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
});

test("getAssertion: DER signature verifies over authData || SHA-256(clientDataJSON)", async () => {
  const { passkey, response: reg } = created;
  const challenge = toB64u(crypto.getRandomValues(new Uint8Array(32)));
  const req: GetRequest = { challenge, rpId: "example.com", allowCredentials: [{ type: "public-key", id: passkey.credential_id }], userVerification: "required" };
  const { response, counter } = await getAssertion(req, ORIGIN, { ...passkey, counter: 7 });
  expect(counter, "counter returned unchanged").toBe(7);

  expect(response.id).toBe(passkey.credential_id);
  expect(response.rawId).toBe(passkey.credential_id);
  expect(response.type).toBe("public-key");
  expect(response.authenticatorAttachment).toBe("platform");
  expect(response.clientExtensionResults).toStrictEqual({});
  expect(response.response.userHandle).toBe(passkey.user_handle);

  const cdjBytes = fromB64u(response.response.clientDataJSON);
  const cdj = JSON.parse(new TextDecoder().decode(cdjBytes));
  expect(Object.keys(cdj)).toStrictEqual(["type", "challenge", "origin", "crossOrigin"]);
  expect(cdj.type).toBe("webauthn.get");
  expect(cdj.challenge).toBe(challenge);
  expect(cdj.origin).toBe(ORIGIN);
  expect(cdj.crossOrigin).toBe(false);

  const authData = fromB64u(response.response.authenticatorData);
  const ad = parseAuthData(authData);
  expect(ad.rpIdHash).toStrictEqual(await sha256(enc.encode("example.com")));
  expect(ad.flags, "flags UP|UV|BE|BS, no AT").toBe(0x01 | 0x04 | 0x08 | 0x10);
  expect(ad.signCount).toBe(0);

  const raw = derToRaw(fromB64u(response.response.signature));
  const signed = concat(authData, await sha256(cdjBytes));
  const alg = { name: "ECDSA", hash: "SHA-256" };
  const curve = { name: "ECDSA", namedCurve: "P-256" };
  const spkiKey = await subtle.importKey("spki", bytes(fromB64u(reg.response.publicKey)), curve, false, ["verify"]);
  expect(await subtle.verify(alg, spkiKey, bytes(raw), bytes(signed)), "signature verifies with SPKI key").toBe(true);

  // Also verify with the key taken from the COSE_Key in the attestation (RP-side path).
  const att = cborDecode(fromB64u(reg.response.attestationObject));
  const cose = cborDecode(parseAuthData(att.get("authData")).coseKeyBytes!);
  const coseKey = await subtle.importKey("raw", bytes(concat([0x04], cose.get(-2), cose.get(-3))), curve, false, ["verify"]);
  expect(await subtle.verify(alg, coseKey, bytes(raw), bytes(signed)), "signature verifies with COSE key").toBe(true);

  // Negative control.
  const tampered = signed.slice();
  tampered[0]! ^= 1;
  expect(await subtle.verify(alg, coseKey, bytes(raw), bytes(tampered))).toBe(false);
});

test("getAssertion: default rpId, no allowCredentials, and wrong-RP rejection", async () => {
  const { passkey } = created;
  const { response } = await getAssertion({ challenge: "AAAA" }, "https://example.com", passkey);
  expect(JSON.parse(new TextDecoder().decode(fromB64u(response.response.clientDataJSON))).origin).toBe("https://example.com");
  await expectReject(getAssertion({ challenge: "AAAA" }, "https://other.org", passkey), (e) => e instanceof PasskeyError && e.name === "NotAllowedError");
  await expectReject(
    getAssertion({ challenge: "AAAA", allowCredentials: [{ type: "public-key", id: "AAAAAAAAAAAAAAAAAAAAAA" }] }, ORIGIN.replace("login.", ""), passkey),
    (e) => e instanceof PasskeyError && e.name === "NotAllowedError",
  );
});

test("createPasskey: falls back without ES256 / for cross-platform; empty params means ES256", async () => {
  const noEs256 = { ...createReq(), pubKeyCredParams: [{ type: "public-key", alg: -257 }] };
  await expectReject(createPasskey(noEs256, ORIGIN), (e) => e instanceof PasskeyFallback);
  expect(errorReply(new PasskeyFallback("x"))).toStrictEqual({ fallback: true });
  const crossPlatform = { ...createReq(), authenticatorSelection: { authenticatorAttachment: "cross-platform" } };
  await expectReject(createPasskey(crossPlatform, ORIGIN), (e) => e instanceof PasskeyFallback);
  const empty = { ...createReq(), pubKeyCredParams: [], extensions: undefined };
  const { response } = await createPasskey(empty, ORIGIN);
  expect(response.clientExtensionResults).toStrictEqual({});
  await expectReject(createPasskey({ ...createReq(), user: { id: "", name: "a", displayName: "" } }, ORIGIN), (e) => e instanceof PasskeyFallback);
  await expectReject(createPasskey({ ...createReq(), rp: { id: "evil.com", name: "x" } }, ORIGIN), (e) => e instanceof PasskeyError && e.name === "SecurityError");
  expect(errorReply(new PasskeyError("SecurityError", "m"))).toStrictEqual({ error: { name: "SecurityError", message: "m" } });
});

test("effectiveRpId: origin/RP ID validation", () => {
  const sec = (fn: () => unknown) => expectThrow(fn, (e) => e instanceof PasskeyError && e.name === "SecurityError");
  expect(effectiveRpId(undefined, ORIGIN)).toBe("login.example.com");
  expect(effectiveRpId("example.com", ORIGIN)).toBe("example.com");
  expect(effectiveRpId("Login.Example.COM", ORIGIN)).toBe("login.example.com");
  expect(effectiveRpId("example.com", "https://login.example.com:8443")).toBe("example.com");
  sec(() => effectiveRpId("evil.com", "https://example.com"));
  sec(() => effectiveRpId("evil.com", ORIGIN));
  sec(() => effectiveRpId("ample.com", "https://example.com"));
  sec(() => effectiveRpId("com", "https://example.com"));
  sec(() => effectiveRpId("co.uk", "https://shop.example.co.uk"));
  expect(effectiveRpId("example.co.uk", "https://shop.example.co.uk")).toBe("example.co.uk");
  sec(() => effectiveRpId("github.io", "https://alice.github.io"));
  sec(() => effectiveRpId("login.example.com", "https://example.com")); // RP ID must not be a subdomain
  sec(() => effectiveRpId(undefined, "http://example.com"));
  sec(() => effectiveRpId("example.com", "http://login.example.com"));
  sec(() => effectiveRpId(undefined, "https://192.168.1.1"));
  sec(() => effectiveRpId(undefined, "ftp://example.com"));
  sec(() => effectiveRpId("", ORIGIN));
  sec(() => effectiveRpId("example.com/", ORIGIN));
  sec(() => effectiveRpId("user@example.com", ORIGIN));
  sec(() => effectiveRpId(undefined, "not a url"));
  expect(effectiveRpId(undefined, "http://localhost:3000")).toBe("localhost");
  expect(effectiveRpId("localhost", "http://localhost:3000")).toBe("localhost");
  expect(effectiveRpId("localhost", "http://app.localhost")).toBe("localhost");
  expect(effectiveRpId(undefined, "https://localhost")).toBe("localhost");
  // The full Public Suffix List (the core's): private suffixes are no RP ID either.
  sec(() => effectiveRpId("myfritz.net", "https://nas.myfritz.net"));
  expect(effectiveRpId("nas.myfritz.net", "https://x.nas.myfritz.net")).toBe("nas.myfritz.net");
  // Whatever a page puts there that isn't text is refused before it reaches the core, which keeps working.
  sec(() => effectiveRpId(123 as unknown as string, ORIGIN));
  sec(() => effectiveRpId({ toString: () => "example.com" } as unknown as string, ORIGIN));
  expect(effectiveRpId("example.com", ORIGIN)).toBe("example.com");
  // The page sees the DOMException message the core words.
  expectThrow(
    () => effectiveRpId("evil.com", ORIGIN),
    (e) => e instanceof PasskeyError && e.message === "The RP ID is not a registrable domain suffix of the origin.",
  );
});

test("matchingPasskeys / excludedPasskeyExists honour rpId and credential lists", () => {
  const mk = (id: string, rp_id: string, discoverable = true): Passkey => ({ ...created.passkey, credential_id: id, rp_id, discoverable });
  const a = mk(toB64u(new Uint8Array(16).fill(1)), "example.com");
  const b = mk(toB64u(new Uint8Array(16).fill(2)), "example.com");
  const c = mk(toB64u(new Uint8Array(16).fill(3)), "other.com");
  const d = mk(toB64u(new Uint8Array(16).fill(4)), "example.com", false);
  const all = [a, b, c, d];
  const ids = (list: Passkey[]) => list.map((p) => p.credential_id);

  expect(ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com" }, ORIGIN, all))).toStrictEqual(ids([a, b]));
  expect(ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com", allowCredentials: [] }, ORIGIN, all))).toStrictEqual(ids([a, b]));
  expect(
    ids(
      matchingPasskeys(
        {
          challenge: "AAAA",
          rpId: "example.com",
          allowCredentials: [
            { type: "public-key", id: b.credential_id },
            { type: "public-key", id: d.credential_id },
          ],
        },
        ORIGIN,
        all,
      ),
    ),
  ).toStrictEqual(ids([b, d]));
  // Padded base64url ids still match; a listed credential of another RP never does.
  expect(
    ids(
      matchingPasskeys(
        {
          challenge: "AAAA",
          rpId: "example.com",
          allowCredentials: [
            { type: "public-key", id: `${a.credential_id}==` },
            { type: "public-key", id: c.credential_id },
          ],
        },
        ORIGIN,
        all,
      ),
    ),
  ).toStrictEqual(ids([a]));
  expect(ids(matchingPasskeys({ challenge: "AAAA" }, ORIGIN, all))).toStrictEqual([]); // rpId defaults to login.example.com
  expect(() => matchingPasskeys({ challenge: "AAAA", rpId: "other.com" }, ORIGIN, all)).toThrow(PasskeyError);

  const excl = (id: string) => ({ ...createReq(), excludeCredentials: [{ type: "public-key", id }] });
  expect(excludedPasskeyExists(excl(a.credential_id), ORIGIN, all)).toBe(true);
  expect(excludedPasskeyExists(excl(c.credential_id), ORIGIN, all)).toBe(false);
});

test("rawSignatureToDer: minimal INTEGER encoding edge cases", () => {
  const r = new Uint8Array(32).fill(0x80); // high bit → 0x00 prefix
  const s = concat(new Uint8Array(3), new Uint8Array(29).fill(0x11)); // leading zeros stripped
  const der = rawSignatureToDer(concat(r, s));
  expect(derToRaw(der)).toStrictEqual(concat(r, s));
  expect(der[3]).toBe(33);
  expect(der[4 + 33 + 1]).toBe(29);
  const zero = rawSignatureToDer(new Uint8Array(64));
  expect([...zero]).toStrictEqual([0x30, 6, 0x02, 1, 0, 0x02, 1, 0]);
});

test("user verification: UV flag only when verified; userVerification reads both request shapes", async () => {
  const { passkey } = created;
  const req = { challenge: "AAAA", rpId: "example.com" };
  const noUv = parseAuthData(fromB64u((await getAssertion(req, ORIGIN, passkey, { uv: false })).response.response.authenticatorData));
  expect(noUv.flags, "flags UP|BE|BS without UV").toBe(0x01 | 0x08 | 0x10);
  const reg = await createPasskey(createReq(), ORIGIN, { uv: false });
  expect(parseAuthData(fromB64u(reg.response.response.authenticatorData)).flags, "create without UV").toBe(0x01 | 0x08 | 0x10 | 0x40);
  expect(userVerification("get", { userVerification: "required" })).toBe("required");
  expect(userVerification("get", { userVerification: "preferred" })).toBe("preferred");
  expect(userVerification("get", { userVerification: "discouraged" })).toBe("discouraged");
  expect(userVerification("create", { authenticatorSelection: { userVerification: "required" } })).toBe("required");
  expect(userVerification("create", { authenticatorSelection: { userVerification: "discouraged" } })).toBe("discouraged");
  // Missing or unknown: the WebAuthn default, "preferred".
  expect(userVerification("create", {})).toBe("preferred");
  expect(userVerification("get", { userVerification: "always" })).toBe("preferred");
  expect(userVerification("get", null)).toBe("preferred");
  // The other request shape's field is not read.
  expect(userVerification("create", { userVerification: "required" })).toBe("preferred");
});

test("base64url round trip", () => {
  for (let n = 0; n < 40; n++) {
    const b = crypto.getRandomValues(new Uint8Array(n));
    expect(b64uEncode(b)).toBe(toB64u(b));
    expect(b64uDecode(toB64u(b))).toStrictEqual(b);
  }
  expect(() => b64uDecode("a+b/")).toThrow(TypeError);
  expect(() => b64uDecode("abcde")).toThrow(TypeError);
});
