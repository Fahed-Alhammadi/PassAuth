// Cryptographic tests for extension/src/background/passkeys.ts.
// Run with plain Node (type stripping):  node extension/test/passkeys.test.mjs

import assert from "node:assert/strict";
import {
  PASSAUTH_AAGUID,
  PasskeyError,
  PasskeyFallback,
  b64uDecode,
  b64uEncode,
  createPasskey,
  effectiveRpId,
  errorReply,
  excludedPasskeyExists,
  getAssertion,
  matchingPasskeys,
  rawSignatureToDer,
} from "../src/background/passkeys.ts";

// ------------------------------------------------------------------ tiny runner

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

async function run() {
  let failed = 0;
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`ok   - ${name}`);
    } catch (e) {
      failed++;
      console.log(`FAIL - ${name}\n${e?.stack ?? e}`);
    }
  }
  console.log(`\n${tests.length - failed}/${tests.length} passed`);
  process.exitCode = failed ? 1 : 0;
}

// ------------------------------------------------------------------ helpers (independent of the code under test)

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
const concat = (...p) => {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) (out.set(x, o), (o += x.length));
  return out;
};
const fromB64u = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const toB64u = (b) => Buffer.from(b).toString("base64url");

/** Minimal CBOR decoder: uint, negint, bytes, text, array, map (→ Map), true/false/null. */
function cborDecode(bytes) {
  let pos = 0;
  const readLen = (info) => {
    if (info < 24) return info;
    const n = { 24: 1, 25: 2, 26: 4 }[info];
    assert.ok(n, `unsupported CBOR length info ${info}`);
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + bytes[pos++];
    return v;
  };
  const item = () => {
    const ib = bytes[pos++];
    const major = ib >> 5;
    const info = ib & 31;
    switch (major) {
      case 0: return readLen(info);
      case 1: return -1 - readLen(info);
      case 2: { const n = readLen(info); const b = bytes.slice(pos, pos + n); pos += n; return b; }
      case 3: { const n = readLen(info); const s = new TextDecoder().decode(bytes.slice(pos, pos + n)); pos += n; return s; }
      case 4: { const n = readLen(info); return Array.from({ length: n }, item); }
      case 5: {
        const n = readLen(info);
        const m = new Map();
        for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); }
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
  assert.equal(pos, bytes.length, "trailing bytes after CBOR item");
  return v;
}

/** Strict DER ECDSA-Sig-Value → raw r||s (32 bytes each). */
function derToRaw(der) {
  let p = 0;
  assert.equal(der[p++], 0x30);
  assert.equal(der[p++], der.length - 2, "SEQUENCE length");
  const int = () => {
    assert.equal(der[p++], 0x02);
    const len = der[p++];
    let v = der.slice(p, p + len);
    p += len;
    assert.ok(len >= 1 && len <= 33);
    assert.equal(v[0] & 0x80, 0, "INTEGER must be positive");
    if (len > 1) assert.ok(!(v[0] === 0 && !(v[1] & 0x80)), "non-minimal INTEGER");
    if (v.length === 33) v = v.slice(1);
    return concat(new Uint8Array(32 - v.length), v);
  };
  const r = int();
  const s = int();
  assert.equal(p, der.length);
  return concat(r, s);
}

function parseAuthData(ad) {
  const out = {
    rpIdHash: ad.slice(0, 32),
    flags: ad[32],
    signCount: new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0),
  };
  if (out.flags & 0x40) {
    out.aaguid = ad.slice(37, 53);
    const idLen = (ad[53] << 8) | ad[54];
    out.credentialId = ad.slice(55, 55 + idLen);
    out.coseKeyBytes = ad.slice(55 + idLen);
  } else {
    assert.equal(ad.length, 37);
  }
  return out;
}

const ORIGIN = "https://login.example.com";
const createReq = () => ({
  rp: { id: "example.com", name: "Example" },
  user: { id: toB64u(enc.encode("user-1234")), name: "alice@example.com", displayName: "Alice" },
  challenge: toB64u(crypto.getRandomValues(new Uint8Array(32))),
  pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
  authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  attestation: "direct",
  extensions: { credProps: true },
});

// ------------------------------------------------------------------ tests

let created; // shared between create and get tests
let createdReq;

test("createPasskey: attestationObject, authData, COSE key, clientDataJSON", async () => {
  createdReq = createReq();
  created = await createPasskey(createdReq, ORIGIN);
  const { passkey, response } = created;
  const r = response.response;

  assert.equal(response.type, "public-key");
  assert.equal(response.authenticatorAttachment, "platform");
  assert.equal(response.id, response.rawId);
  assert.equal(fromB64u(response.rawId).length, 16);
  assert.deepEqual(response.clientExtensionResults, { credProps: { rk: true } });
  assert.deepEqual(r.transports, ["internal", "hybrid"]);
  assert.equal(r.publicKeyAlgorithm, -7);

  // clientDataJSON: byte-exact.
  const cdj = new TextDecoder().decode(fromB64u(r.clientDataJSON));
  assert.equal(cdj, `{"type":"webauthn.create","challenge":"${createdReq.challenge}","origin":"${ORIGIN}","crossOrigin":false}`);

  // attestationObject: {"fmt":"none","attStmt":{},"authData":bytes} in canonical order.
  const attObjBytes = fromB64u(r.attestationObject);
  const att = cborDecode(attObjBytes);
  assert.deepEqual([...att.keys()], ["fmt", "attStmt", "authData"]);
  assert.equal(att.get("fmt"), "none");
  assert.ok(att.get("attStmt") instanceof Map && att.get("attStmt").size === 0);
  const authData = att.get("authData");
  assert.deepEqual(authData, fromB64u(r.authenticatorData));

  const ad = parseAuthData(authData);
  assert.deepEqual(ad.rpIdHash, await sha256(enc.encode("example.com")));
  assert.equal(ad.flags, 0x01 | 0x04 | 0x08 | 0x10 | 0x40, "flags UP|UV|BE|BS|AT");
  assert.equal(ad.signCount, 0);
  assert.deepEqual(ad.aaguid, new Uint8Array(PASSAUTH_AAGUID));
  assert.equal(toB64u(ad.credentialId), response.id);

  // COSE_Key {1:2, 3:-7, -1:1, -2:x, -3:y}, canonical order, and equal to the SPKI key.
  const cose = cborDecode(ad.coseKeyBytes);
  assert.deepEqual([...cose.keys()], [1, 3, -1, -2, -3]);
  assert.equal(cose.get(1), 2);
  assert.equal(cose.get(3), -7);
  assert.equal(cose.get(-1), 1);
  assert.equal(cose.get(-2).length, 32);
  assert.equal(cose.get(-3).length, 32);
  const spkiKey = await subtle.importKey("spki", fromB64u(r.publicKey), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const spkiRaw = new Uint8Array(await subtle.exportKey("raw", spkiKey));
  assert.deepEqual(spkiRaw, concat([0x04], cose.get(-2), cose.get(-3)));

  // Stored passkey.
  assert.equal(passkey.credential_id, response.id);
  assert.equal(passkey.rp_id, "example.com");
  assert.equal(passkey.rp_name, "Example");
  assert.equal(passkey.user_handle, createdReq.user.id);
  assert.equal(passkey.user_name, "alice@example.com");
  assert.equal(passkey.user_display_name, "Alice");
  assert.equal(passkey.algorithm, -7);
  assert.equal(passkey.counter, 0);
  assert.equal(passkey.discoverable, true);
  assert.ok(Math.abs(passkey.created_at - Date.now() / 1000) < 60);
  await subtle.importKey("pkcs8", fromB64u(passkey.private_key), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
});

test("getAssertion: DER signature verifies over authData || SHA-256(clientDataJSON)", async () => {
  const { passkey, response: reg } = created;
  const challenge = toB64u(crypto.getRandomValues(new Uint8Array(32)));
  const req = { challenge, rpId: "example.com", allowCredentials: [{ type: "public-key", id: passkey.credential_id }], userVerification: "required" };
  const { response, counter } = await getAssertion(req, ORIGIN, { ...passkey, counter: 7 });
  assert.equal(counter, 7, "counter returned unchanged");

  assert.equal(response.id, passkey.credential_id);
  assert.equal(response.rawId, passkey.credential_id);
  assert.equal(response.type, "public-key");
  assert.equal(response.authenticatorAttachment, "platform");
  assert.deepEqual(response.clientExtensionResults, {});
  assert.equal(response.response.userHandle, passkey.user_handle);

  const cdjBytes = fromB64u(response.response.clientDataJSON);
  const cdj = JSON.parse(new TextDecoder().decode(cdjBytes));
  assert.deepEqual(Object.keys(cdj), ["type", "challenge", "origin", "crossOrigin"]);
  assert.equal(cdj.type, "webauthn.get");
  assert.equal(cdj.challenge, challenge);
  assert.equal(cdj.origin, ORIGIN);
  assert.equal(cdj.crossOrigin, false);

  const authData = fromB64u(response.response.authenticatorData);
  const ad = parseAuthData(authData);
  assert.deepEqual(ad.rpIdHash, await sha256(enc.encode("example.com")));
  assert.equal(ad.flags, 0x01 | 0x04 | 0x08 | 0x10, "flags UP|UV|BE|BS, no AT");
  assert.equal(ad.signCount, 0);

  const raw = derToRaw(fromB64u(response.response.signature));
  const signed = concat(authData, await sha256(cdjBytes));
  const alg = { name: "ECDSA", hash: "SHA-256" };
  const curve = { name: "ECDSA", namedCurve: "P-256" };
  const spkiKey = await subtle.importKey("spki", fromB64u(reg.response.publicKey), curve, false, ["verify"]);
  assert.ok(await subtle.verify(alg, spkiKey, raw, signed), "signature verifies with SPKI key");

  // Also verify with the key taken from the COSE_Key in the attestation (RP-side path).
  const att = cborDecode(fromB64u(reg.response.attestationObject));
  const cose = cborDecode(parseAuthData(att.get("authData")).coseKeyBytes);
  const coseKey = await subtle.importKey("raw", concat([0x04], cose.get(-2), cose.get(-3)), curve, false, ["verify"]);
  assert.ok(await subtle.verify(alg, coseKey, raw, signed), "signature verifies with COSE key");

  // Negative control.
  const tampered = signed.slice();
  tampered[0] ^= 1;
  assert.equal(await subtle.verify(alg, coseKey, raw, tampered), false);
});

test("getAssertion: default rpId, no allowCredentials, and wrong-RP rejection", async () => {
  const { passkey } = created;
  const { response } = await getAssertion({ challenge: "AAAA" }, "https://example.com", passkey);
  assert.equal(JSON.parse(Buffer.from(response.response.clientDataJSON, "base64url")).origin, "https://example.com");
  await assert.rejects(getAssertion({ challenge: "AAAA" }, "https://other.org", passkey), (e) => e instanceof PasskeyError && e.name === "NotAllowedError");
  await assert.rejects(
    getAssertion({ challenge: "AAAA", allowCredentials: [{ type: "public-key", id: "AAAAAAAAAAAAAAAAAAAAAA" }] }, ORIGIN.replace("login.", ""), passkey),
    (e) => e instanceof PasskeyError && e.name === "NotAllowedError",
  );
});

test("createPasskey: falls back without ES256 / for cross-platform; empty params means ES256", async () => {
  const noEs256 = { ...createReq(), pubKeyCredParams: [{ type: "public-key", alg: -257 }] };
  await assert.rejects(createPasskey(noEs256, ORIGIN), (e) => e instanceof PasskeyFallback);
  assert.deepEqual(errorReply(new PasskeyFallback("x")), { fallback: true });
  const crossPlatform = { ...createReq(), authenticatorSelection: { authenticatorAttachment: "cross-platform" } };
  await assert.rejects(createPasskey(crossPlatform, ORIGIN), (e) => e instanceof PasskeyFallback);
  const empty = { ...createReq(), pubKeyCredParams: [], extensions: undefined };
  const { response } = await createPasskey(empty, ORIGIN);
  assert.deepEqual(response.clientExtensionResults, {});
  await assert.rejects(createPasskey({ ...createReq(), user: { id: "", name: "a", displayName: "" } }, ORIGIN), (e) => e instanceof PasskeyFallback);
  await assert.rejects(createPasskey({ ...createReq(), rp: { id: "evil.com", name: "x" } }, ORIGIN), (e) => e instanceof PasskeyError && e.name === "SecurityError");
  assert.deepEqual(errorReply(new PasskeyError("SecurityError", "m")), { error: { name: "SecurityError", message: "m" } });
});

test("effectiveRpId: origin/RP ID validation", () => {
  const sec = (fn) => assert.throws(fn, (e) => e instanceof PasskeyError && e.name === "SecurityError");
  assert.equal(effectiveRpId(undefined, ORIGIN), "login.example.com");
  assert.equal(effectiveRpId("example.com", ORIGIN), "example.com");
  assert.equal(effectiveRpId("Login.Example.COM", ORIGIN), "login.example.com");
  assert.equal(effectiveRpId("example.com", "https://login.example.com:8443"), "example.com");
  sec(() => effectiveRpId("evil.com", "https://example.com"));
  sec(() => effectiveRpId("evil.com", ORIGIN));
  sec(() => effectiveRpId("ample.com", "https://example.com"));
  sec(() => effectiveRpId("com", "https://example.com"));
  sec(() => effectiveRpId("co.uk", "https://shop.example.co.uk"));
  assert.equal(effectiveRpId("example.co.uk", "https://shop.example.co.uk"), "example.co.uk");
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
  assert.equal(effectiveRpId(undefined, "http://localhost:3000"), "localhost");
  assert.equal(effectiveRpId("localhost", "http://localhost:3000"), "localhost");
  assert.equal(effectiveRpId("localhost", "http://app.localhost"), "localhost");
  assert.equal(effectiveRpId(undefined, "https://localhost"), "localhost");
});

test("matchingPasskeys / excludedPasskeyExists honour rpId and credential lists", () => {
  const mk = (id, rp_id, discoverable = true) => ({ ...created.passkey, credential_id: id, rp_id, discoverable });
  const a = mk(toB64u(new Uint8Array(16).fill(1)), "example.com");
  const b = mk(toB64u(new Uint8Array(16).fill(2)), "example.com");
  const c = mk(toB64u(new Uint8Array(16).fill(3)), "other.com");
  const d = mk(toB64u(new Uint8Array(16).fill(4)), "example.com", false);
  const all = [a, b, c, d];
  const ids = (list) => list.map((p) => p.credential_id);

  assert.deepEqual(ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com" }, ORIGIN, all)), ids([a, b]));
  assert.deepEqual(ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com", allowCredentials: [] }, ORIGIN, all)), ids([a, b]));
  assert.deepEqual(
    ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com", allowCredentials: [{ type: "public-key", id: b.credential_id }, { type: "public-key", id: d.credential_id }] }, ORIGIN, all)),
    ids([b, d]),
  );
  // Padded base64url ids still match; a listed credential of another RP never does.
  assert.deepEqual(
    ids(matchingPasskeys({ challenge: "AAAA", rpId: "example.com", allowCredentials: [{ type: "public-key", id: `${a.credential_id}==` }, { type: "public-key", id: c.credential_id }] }, ORIGIN, all)),
    ids([a]),
  );
  assert.deepEqual(ids(matchingPasskeys({ challenge: "AAAA" }, ORIGIN, all)), []); // rpId defaults to login.example.com
  assert.throws(() => matchingPasskeys({ challenge: "AAAA", rpId: "other.com" }, ORIGIN, all), PasskeyError);

  const excl = (id) => ({ ...createReq(), excludeCredentials: [{ type: "public-key", id }] });
  assert.equal(excludedPasskeyExists(excl(a.credential_id), ORIGIN, all), true);
  assert.equal(excludedPasskeyExists(excl(c.credential_id), ORIGIN, all), false);
});

test("rawSignatureToDer: minimal INTEGER encoding edge cases", () => {
  const r = new Uint8Array(32).fill(0x80); // high bit → 0x00 prefix
  const s = concat(new Uint8Array(3), new Uint8Array(29).fill(0x11)); // leading zeros stripped
  const der = rawSignatureToDer(concat(r, s));
  assert.deepEqual(derToRaw(der), concat(r, s));
  assert.equal(der[3], 33);
  assert.equal(der[4 + 33 + 1], 29);
  const zero = rawSignatureToDer(new Uint8Array(64));
  assert.deepEqual([...zero], [0x30, 6, 0x02, 1, 0, 0x02, 1, 0]);
});

test("base64url round trip", () => {
  for (let n = 0; n < 40; n++) {
    const b = crypto.getRandomValues(new Uint8Array(n));
    assert.equal(b64uEncode(b), toB64u(b));
    assert.deepEqual(b64uDecode(toB64u(b)), b);
  }
  assert.throws(() => b64uDecode("a+b/"), TypeError);
  assert.throws(() => b64uDecode("abcde"), TypeError);
});

await run();
