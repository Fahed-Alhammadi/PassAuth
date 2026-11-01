// PassAuth software WebAuthn authenticator (ES256 only).
//
// Pure functions on top of WebCrypto (globalThis.crypto.subtle); no chrome.*
// calls, so this module runs unchanged in the service worker and in Node tests.
// Implemented from the W3C WebAuthn Level 3 and CTAP 2.1 specifications.
//
// Errors:
//   - PasskeyFallback: PassAuth cannot / should not handle the request; the
//     page must call the browser's native implementation (reply `{fallback:true}`).
//   - PasskeyError:    surface to the page as DOMException(message, name).
// Use `errorReply(e)` to turn any thrown value into a PasskeyRuntimeReply.

import type {
  AuthenticationResponseJSON,
  ClientExtensionResultsJSON,
  CreateRequest,
  GetRequest,
  Passkey,
  PasskeyRuntimeReply,
  RegistrationResponseJSON,
} from "../shared/passkey-types";

type Bytes = Uint8Array<ArrayBuffer>;

/** PassAuth authenticator AAGUID (random, fixed): bbc747a1-4ff9-29df-6533-dfaa44f86a18. */
export const PASSAUTH_AAGUID: Uint8Array = new Uint8Array([
  0xbb, 0xc7, 0x47, 0xa1, 0x4f, 0xf9, 0x29, 0xdf, 0x65, 0x33, 0xdf, 0xaa, 0x44, 0xf8, 0x6a, 0x18,
]);

export const COSE_ALG_ES256 = -7;

const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified (the user confirms in PassAuth's UI)
const FLAG_BE = 0x08; // backup eligible (synced credential)
const FLAG_BS = 0x10; // backup state
const FLAG_AT = 0x40; // attested credential data included
const ASSERTION_FLAGS = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
const CREATE_FLAGS = ASSERTION_FLAGS | FLAG_AT;

const TRANSPORTS = ["internal", "hybrid"];
const EC_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" } as const;

// ------------------------------------------------------------------ errors

/** An error the page should see as `new DOMException(message, name)`. */
export class PasskeyError extends Error {
  constructor(name: string, message: string) {
    super(message);
    this.name = name;
  }
}

/** PassAuth does not handle this request; let the browser's own authenticators handle it. */
export class PasskeyFallback extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "PasskeyFallback";
  }
}

/** Map anything thrown by this module (or the caller) to a runtime reply. */
export function errorReply(e: unknown): PasskeyRuntimeReply {
  if (e instanceof PasskeyFallback) return { fallback: true };
  if (e instanceof PasskeyError) return { error: { name: e.name, message: e.message } };
  return { error: { name: "NotAllowedError", message: "The operation failed." } };
}

// ------------------------------------------------------------------ base64url

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_LOOKUP: Record<string, number> = {};
for (let i = 0; i < B64U.length; i++) B64U_LOOKUP[B64U[i]!] = i;

/** Unpadded base64url encoding. */
export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]! + B64U[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64U[n >> 18]! + B64U[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64U[n >> 18]! + B64U[(n >> 12) & 63]! + B64U[(n >> 6) & 63]!;
  }
  return out;
}

/** Decode base64url (padding tolerated). Throws TypeError on malformed input. */
export function b64uDecode(s: string): Bytes {
  if (typeof s !== "string") throw new TypeError("base64url: not a string");
  const str = s.replace(/=+$/, "");
  if (!/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) throw new TypeError("base64url: malformed");
  const out = new Uint8Array(Math.floor((str.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < str.length; i += 4) {
    const a = B64U_LOOKUP[str[i]!]!;
    const b = B64U_LOOKUP[str[i + 1]!]!;
    const c = i + 2 < str.length ? B64U_LOOKUP[str[i + 2]!]! : 0;
    const d = i + 3 < str.length ? B64U_LOOKUP[str[i + 3]!]! : 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    out[o++] = n >> 16;
    if (i + 2 < str.length) out[o++] = (n >> 8) & 255;
    if (i + 3 < str.length) out[o++] = n & 255;
  }
  return out;
}

/** Canonical (unpadded) form of a base64url string, or null if malformed. */
function canonicalB64u(s: unknown): string | null {
  if (typeof s !== "string") return null;
  try {
    return b64uEncode(b64uDecode(s));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ bytes

function concat(...parts: (Uint8Array | number[])[]): Bytes {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function utf8(s: string): Bytes {
  return new TextEncoder().encode(s) as Bytes;
}

async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function u32be(n: number): Bytes {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

// ------------------------------------------------------------------ CBOR (RFC 8949, minimal)

/** Values this encoder supports. Maps are `Map`s with integer or text keys. */
export type CborValue = number | string | boolean | null | Uint8Array | CborValue[] | Map<number | string, CborValue>;

function cborHead(major: number, n: number): number[] {
  const m = major << 5;
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError("CBOR: length/int out of range");
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 255];
  return [m | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function cborParts(v: CborValue, out: (Uint8Array | number[])[]): void {
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new TypeError("CBOR: only integers are supported");
    out.push(v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v));
  } else if (typeof v === "string") {
    const b = utf8(v);
    out.push(cborHead(3, b.length), b);
  } else if (typeof v === "boolean") {
    out.push([v ? 0xf5 : 0xf4]);
  } else if (v === null) {
    out.push([0xf6]);
  } else if (v instanceof Uint8Array) {
    out.push(cborHead(2, v.length), v);
  } else if (Array.isArray(v)) {
    out.push(cborHead(4, v.length));
    for (const item of v) cborParts(item, out);
  } else if (v instanceof Map) {
    // CTAP2 canonical order: keys sorted by encoded length, then bytewise.
    const entries = [...v].map(([k, val]) => ({ k: cborEncode(k), val }));
    entries.sort((x, y) => {
      if (x.k.length !== y.k.length) return x.k.length - y.k.length;
      for (let i = 0; i < x.k.length; i++) if (x.k[i] !== y.k[i]) return x.k[i]! - y.k[i]!;
      return 0;
    });
    out.push(cborHead(5, entries.length));
    for (const e of entries) {
      out.push(e.k);
      cborParts(e.val, out);
    }
  } else {
    throw new TypeError("CBOR: unsupported value");
  }
}

/** Deterministic (CTAP2-canonical) CBOR encoding. */
export function cborEncode(v: CborValue): Bytes {
  const parts: (Uint8Array | number[])[] = [];
  cborParts(v, parts);
  return concat(...parts);
}

// ------------------------------------------------------------------ ECDSA signature encoding

/** Convert a WebCrypto raw ECDSA signature (r||s, 32 bytes each) to ASN.1 DER. */
export function rawSignatureToDer(raw: Uint8Array): Bytes {
  if (raw.length !== 64) throw new RangeError("ECDSA P-256 raw signature must be 64 bytes");
  const int = (b: Uint8Array): Bytes => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v: Uint8Array = b.subarray(i);
    if (v[0]! & 0x80) v = concat([0], v);
    return concat([0x02, v.length], v);
  };
  const r = int(raw.subarray(0, 32));
  const s = int(raw.subarray(32, 64));
  return concat([0x30, r.length + s.length], r, s);
}

// ------------------------------------------------------------------ RP ID validation

/**
 * Small built-in list of multi-label public suffixes (ICANN + common private
 * hosting suffixes). LIMITATION: this is not the full Public Suffix List, so a
 * registrable-domain check against an unlisted multi-label suffix (e.g.
 * "pvt.k12.ma.us", wildcard rules like "*.ck") can wrongly succeed. Single-label
 * suffixes ("com", "app", ...) are always rejected.
 */
const MULTI_LABEL_PUBLIC_SUFFIXES = new Set<string>([
  // United Kingdom
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
  // Australia / New Zealand
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "geek.nz", "school.nz",
  // Asia
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "ad.jp", "ed.jp", "lg.jp",
  "co.kr", "ne.kr", "or.kr", "re.kr", "go.kr", "ac.kr",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "com.hk", "net.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
  "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw", "idv.tw",
  "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
  "com.my", "net.my", "org.my", "edu.my", "gov.my",
  "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in", "res.in",
  "co.id", "or.id", "ac.id", "go.id", "web.id", "my.id",
  "com.ph", "net.ph", "org.ph", "gov.ph",
  "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
  "co.th", "in.th", "ac.th", "go.th", "or.th",
  "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
  "com.bd", "com.np", "com.lk",
  // Middle East / Africa
  "com.sa", "net.sa", "org.sa", "edu.sa", "gov.sa", "med.sa",
  "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae", "sch.ae",
  "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb",
  "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
  "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "gen.tr",
  "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
  "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
  "com.ng", "org.ng", "gov.ng", "co.ke", "or.ke", "ac.ke", "co.tz", "co.ug", "com.gh", "co.ma",
  // Americas
  "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
  "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
  "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
  "com.co", "net.co", "org.co", "gov.co", "edu.co",
  "com.pe", "net.pe", "org.pe", "gob.pe", "com.ve", "co.ve", "com.ec", "com.uy", "com.py", "com.bo",
  "cl.cl", "gob.cl", "co.cr", "com.gt", "com.do", "com.pr",
  // Europe
  "co.at", "or.at", "ac.at", "gv.at", "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
  "com.ua", "net.ua", "org.ua", "gov.ua", "com.ru", "net.ru", "org.ru", "com.gr", "com.cy", "com.mt",
  "com.pt", "com.es", "nom.es", "org.es", "com.ro", "co.hu", "com.hr", "co.rs", "com.ee", "co.no",
  // Common private hosting suffixes
  "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "blogspot.com", "cloudfront.net",
  "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
  "azurewebsites.net", "azurestaticapps.net", "s3.amazonaws.com", "elasticbeanstalk.com",
  "onrender.com", "fly.dev", "glitch.me", "repl.co", "ngrok.io", "ngrok.app", "ngrok-free.app",
  "trycloudflare.com", "duckdns.org", "dyndns.org", "no-ip.org", "eu.org", "readthedocs.io",
]);

function isPublicSuffix(domain: string): boolean {
  if (!domain.includes(".")) return domain !== "localhost";
  return MULTI_LABEL_PUBLIC_SUFFIXES.has(domain);
}

function isIpHost(host: string): boolean {
  return host.startsWith("[") || /^\d+\.\d+\.\d+\.\d+$/.test(host);
}

/** Canonical (lower-case, punycoded) domain, or null if not a valid domain string. */
function canonicalDomain(s: string): string | null {
  if (s.length === 0 || s.length > 253 || /[\s/\\?#@:[\]%*]/.test(s)) return null;
  let host: string;
  try {
    host = new URL(`https://${s}/`).hostname;
  } catch {
    return null;
  }
  if (host === "" || host.startsWith(".") || host.endsWith(".") || host.includes("..") || isIpHost(host)) return null;
  return host;
}

function securityError(message: string): PasskeyError {
  return new PasskeyError("SecurityError", message);
}

function parseOrigin(origin: string): { origin: string; host: string } {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw securityError("Invalid origin.");
  }
  if (url.origin !== origin) throw securityError("Invalid origin.");
  const host = url.hostname;
  const localhost = host === "localhost" || host.endsWith(".localhost");
  if (!(url.protocol === "https:" || (url.protocol === "http:" && localhost))) {
    throw securityError("WebAuthn requires a secure (https) origin.");
  }
  if (isIpHost(host)) throw securityError("The origin's host is not a valid domain.");
  return { origin: url.origin, host };
}

/**
 * The RP ID to use for a request from `origin`: `requestedRpId` if it equals the
 * origin's host or is a registrable-domain suffix of it, otherwise throws a
 * SecurityError PasskeyError. Defaults to the origin's host. Only https origins
 * (plus http://localhost and http://*.localhost) are accepted.
 */
export function effectiveRpId(requestedRpId: string | undefined, origin: string): string {
  const { host } = parseOrigin(origin);
  if (requestedRpId == null) return host;
  if (typeof requestedRpId !== "string") throw securityError("Invalid RP ID.");
  const rpId = canonicalDomain(requestedRpId);
  if (rpId === null) throw securityError("Invalid RP ID.");
  if (rpId === host) return rpId;
  if (!host.endsWith(`.${rpId}`) || isPublicSuffix(rpId)) {
    throw securityError("The RP ID is not a registrable domain suffix of the origin.");
  }
  return rpId;
}

// ------------------------------------------------------------------ request validation

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Malformed requests fall back to the browser, which raises the spec-mandated TypeError. */
function malformed(what: string): PasskeyFallback {
  return new PasskeyFallback(`malformed request: ${what}`);
}

function descriptorIds(list: unknown, what: string): Set<string> {
  const ids = new Set<string>();
  if (list === undefined) return ids;
  if (!Array.isArray(list)) throw malformed(what);
  for (const d of list) {
    if (!isObj(d)) throw malformed(what);
    const id = canonicalB64u(d.id);
    if (id === null) throw malformed(what);
    if (d.type === "public-key") ids.add(id);
  }
  return ids;
}

function checkCreateRequest(req: CreateRequest): void {
  if (!isObj(req)) throw malformed("options");
  if (!isObj(req.rp) || typeof req.rp.name !== "string") throw malformed("rp");
  if (req.rp.id !== undefined && typeof req.rp.id !== "string") throw malformed("rp.id");
  if (!isObj(req.user) || typeof req.user.name !== "string") throw malformed("user");
  if (req.user.displayName !== undefined && typeof req.user.displayName !== "string") throw malformed("user.displayName");
  const userId = canonicalB64u(req.user.id);
  if (userId === null) throw malformed("user.id");
  const userIdLen = b64uDecode(userId).length;
  if (userIdLen < 1 || userIdLen > 64) throw malformed("user.id length");
  if (canonicalB64u(req.challenge) === null) throw malformed("challenge");
  if (!Array.isArray(req.pubKeyCredParams)) throw malformed("pubKeyCredParams");
  descriptorIds(req.excludeCredentials, "excludeCredentials");
  if (req.authenticatorSelection !== undefined && !isObj(req.authenticatorSelection)) throw malformed("authenticatorSelection");
}

function checkGetRequest(req: GetRequest): void {
  if (!isObj(req)) throw malformed("options");
  if (canonicalB64u(req.challenge) === null) throw malformed("challenge");
  if (req.rpId !== undefined && typeof req.rpId !== "string") throw malformed("rpId");
  descriptorIds(req.allowCredentials, "allowCredentials");
}

/** True when PassAuth can satisfy the create request's algorithm/attachment constraints (ES256, platform). */
export function supportsCreateRequest(req: CreateRequest): boolean {
  const params = Array.isArray(req?.pubKeyCredParams) ? req.pubKeyCredParams : [];
  // An empty list means "ES256 and RS256" per WebAuthn §5.1.3 step 10.
  const es256 = params.length === 0 || params.some((p) => isObj(p) && p.type === "public-key" && p.alg === COSE_ALG_ES256);
  const attachment = req?.authenticatorSelection?.authenticatorAttachment;
  return es256 && attachment !== "cross-platform";
}

// ------------------------------------------------------------------ WebAuthn data structures

function clientDataJSON(type: "webauthn.create" | "webauthn.get", challenge: string, origin: string): Bytes {
  // Byte-exact key order per WebAuthn L3 §5.8.1.1 (limited verification algorithm compatible).
  return utf8(
    `{"type":${JSON.stringify(type)},"challenge":${JSON.stringify(challenge)},"origin":${JSON.stringify(origin)},"crossOrigin":false}`,
  );
}

/** COSE_Key (RFC 9053) for an uncompressed P-256 point 0x04||x||y. */
function coseEc2Key(rawPublicKey: Uint8Array): Bytes {
  if (rawPublicKey.length !== 65 || rawPublicKey[0] !== 0x04) throw new Error("unexpected EC public key format");
  return cborEncode(
    new Map<number, CborValue>([
      [1, 2], // kty: EC2
      [3, COSE_ALG_ES256], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, rawPublicKey.slice(1, 33)], // x
      [-3, rawPublicKey.slice(33, 65)], // y
    ]),
  );
}

function clientExtensionResults(extensions: unknown, create: boolean): ClientExtensionResultsJSON {
  const out: ClientExtensionResultsJSON = {};
  if (create && isObj(extensions) && extensions.credProps === true) out.credProps = { rk: true };
  return out;
}

// ------------------------------------------------------------------ public API

/** True if `all` holds a passkey listed in the request's excludeCredentials (→ InvalidStateError after user consent). */
export function excludedPasskeyExists(req: CreateRequest, origin: string, all: Passkey[]): boolean {
  const rpId = effectiveRpId(req.rp?.id, origin);
  const excluded = descriptorIds(req.excludeCredentials, "excludeCredentials");
  return all.some((p) => p.rp_id === rpId && excluded.has(canonicalB64u(p.credential_id) ?? ""));
}

/**
 * Create a new discoverable ES256 passkey. Call only after the user confirmed.
 * Throws PasskeyFallback when the request is unsupported (no ES256, cross-platform
 * attachment) or malformed, PasskeyError(SecurityError) for a bad origin / RP ID.
 */
export async function createPasskey(
  req: CreateRequest,
  origin: string,
): Promise<{ passkey: Passkey; response: RegistrationResponseJSON }> {
  checkCreateRequest(req);
  const rpId = effectiveRpId(req.rp.id, origin);
  if (!supportsCreateRequest(req)) throw new PasskeyFallback("unsupported algorithm or attachment");
  const { origin: normOrigin } = parseOrigin(origin);

  const keyPair = await crypto.subtle.generateKey(EC_P256, true, ["sign", "verify"]);
  const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const credentialId = crypto.getRandomValues(new Uint8Array(16));

  const authData = concat(
    await sha256(utf8(rpId)),
    [CREATE_FLAGS],
    u32be(0),
    PASSAUTH_AAGUID,
    [credentialId.length >> 8, credentialId.length & 255],
    credentialId,
    coseEc2Key(rawPublicKey),
  );
  const cdj = clientDataJSON("webauthn.create", canonicalB64u(req.challenge)!, normOrigin);
  const attestationObject = cborEncode(
    new Map<string, CborValue>([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", authData],
    ]),
  );

  const id = b64uEncode(credentialId);
  const passkey: Passkey = {
    credential_id: id,
    rp_id: rpId,
    rp_name: req.rp.name,
    user_handle: canonicalB64u(req.user.id)!,
    user_name: req.user.name,
    user_display_name: req.user.displayName ?? "",
    algorithm: COSE_ALG_ES256,
    private_key: b64uEncode(pkcs8),
    counter: 0,
    discoverable: true,
    created_at: Math.floor(Date.now() / 1000),
  };
  const response: RegistrationResponseJSON = {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: b64uEncode(cdj),
      attestationObject: b64uEncode(attestationObject),
      authenticatorData: b64uEncode(authData),
      transports: [...TRANSPORTS],
      publicKey: b64uEncode(spki),
      publicKeyAlgorithm: COSE_ALG_ES256,
    },
    clientExtensionResults: clientExtensionResults(req.extensions, true),
  };
  return { passkey, response };
}

/**
 * Passkeys usable for `req` from `origin`: same RP ID, ES256, and listed in
 * allowCredentials (or discoverable when allowCredentials is empty/absent).
 * Throws PasskeyError(SecurityError) for a bad origin / RP ID.
 */
export function matchingPasskeys(req: GetRequest, origin: string, all: Passkey[]): Passkey[] {
  checkGetRequest(req);
  const rpId = effectiveRpId(req.rpId, origin);
  const allowed = descriptorIds(req.allowCredentials, "allowCredentials");
  const requireListed = Array.isArray(req.allowCredentials) && req.allowCredentials.length > 0;
  return all.filter((p) => {
    if (p.rp_id !== rpId || p.algorithm !== COSE_ALG_ES256) return false;
    return requireListed ? allowed.has(canonicalB64u(p.credential_id) ?? "") : p.discoverable;
  });
}

/**
 * Sign an assertion with `passkey` (chosen and confirmed by the user). The
 * signature counter is always 0 (synced passkey); the stored counter is
 * returned unchanged.
 */
export async function getAssertion(
  req: GetRequest,
  origin: string,
  passkey: Passkey,
): Promise<{ response: AuthenticationResponseJSON; counter: number }> {
  if (matchingPasskeys(req, origin, [passkey]).length !== 1) {
    throw new PasskeyError("NotAllowedError", "The selected passkey is not valid for this request.");
  }
  const rpId = effectiveRpId(req.rpId, origin);
  const { origin: normOrigin } = parseOrigin(origin);

  const authData = concat(await sha256(utf8(rpId)), [ASSERTION_FLAGS], u32be(0));
  const cdj = clientDataJSON("webauthn.get", canonicalB64u(req.challenge)!, normOrigin);
  const key = await crypto.subtle.importKey("pkcs8", b64uDecode(passkey.private_key), EC_P256, false, ["sign"]);
  const rawSig = new Uint8Array(await crypto.subtle.sign(ECDSA_SHA256, key, concat(authData, await sha256(cdj))));

  const id = canonicalB64u(passkey.credential_id)!;
  const response: AuthenticationResponseJSON = {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: b64uEncode(cdj),
      authenticatorData: b64uEncode(authData),
      signature: b64uEncode(rawSignatureToDer(rawSig)),
    },
    clientExtensionResults: clientExtensionResults(req.extensions, false),
  };
  const userHandle = canonicalB64u(passkey.user_handle);
  if (userHandle) response.response.userHandle = userHandle;
  return { response, counter: passkey.counter };
}
