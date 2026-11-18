/**
 * A stand-in for the WASM core (crates/core-wasm) with the crypto surface the
 * background uses. "Encryption" is JSON plus a tag naming the vault key that
 * wrapped the item key, so an item encrypted under a replaced vault key fails
 * to open, as with the real core. The site logic (host names, matching, the save
 * rule, passkey targets, RP IDs, sign-in phrases, the item edit counter check) is the real core's; item writes raise
 * the item's edit counter `rev` like the core's. Vault manifests are the real core's too (test/manifest-key.ts).
 * Signed sharing (which every server this app talks to has) is a stand-in that finds nothing wrong: the account opens
 * or makes a signing identity, every vault row passes its check, nothing is pinned. Its rules are tested with the real
 * core in signed-sharing.test.ts. Used through
 *   vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module())
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { vi } from "vitest";
import type * as Core from "../src/wasm/passauth_core";
import { defaults } from "./fake-server";
import { loadManifests, manifestKey } from "./manifest-key";

/** Knobs a test turns: hold `init` open, count calls. */
export const control = {
  init: (): Promise<unknown> => Promise.resolve(),
  restored: 0,
  /** Account.rewrap calls (PIN copies made). */
  rewrapped: 0,
  /** The account id every fake account authenticates as (the fake server's user). */
  userId: "u-1",
  /** A bundle with this `account_id` isn't one the fake account authenticates (`matchesBundle`: false). */
  foreignAccountId: "acc-foreign",
};

let seq = 0;

const revOf = (item: unknown): number => {
  const r = (item as { rev?: unknown } | null)?.rev;
  return typeof r === "number" ? r : 0;
};

export class FakeVaultKey {
  constructor(public tag: string) {}
  free() {}
  /** Signed sharing: the key's id is its name; any roster matches. */
  keyId() {
    return this.tag;
  }
  epochPin(_vaultId: string, epoch: number) {
    return { key_id: this.tag, epoch };
  }
  matchesRoster() {
    return true;
  }
  /** Vault manifests: the real core's, bound to this key's name. */
  manifestVerify(vaultId: string, epoch: number, seq: number, sealed: string | null | undefined, remembered: number | null | undefined, items: unknown) {
    return manifestKey(this.tag).manifestVerify(vaultId, epoch, seq, sealed, remembered, items);
  }
  manifestStart(vaultId: string, epoch: number, version: number, items: unknown) {
    return manifestKey(this.tag).manifestStart(vaultId, epoch, version, items);
  }
  manifestNext(vaultId: string, epoch: number, seq: number, sealed: string, removed: unknown, added: unknown) {
    return manifestKey(this.tag).manifestNext(vaultId, epoch, seq, sealed, removed, added);
  }
  private check(enc: { key: string }) {
    if (!enc.key.startsWith(`${this.tag}:`)) throw new Error("decrypt_failed");
  }
  decryptMeta(_id: string, meta: string) {
    return JSON.parse(meta);
  }
  decryptItem(enc: { key: string; data: string }) {
    this.check(enc);
    return JSON.parse(enc.data);
  }
  /** Like the core: the item's edit counter `rev` one higher than the item given (1 for a new item). */
  encryptItem(item: unknown, id: string, vault_id: string) {
    return { id, vault_id, key: `${this.tag}:${++seq}`, data: JSON.stringify({ ...(item as object), rev: revOf(item) + 1 }) };
  }
  /** Like the core: `rev` one higher than the higher of the stored item's and the given one's. */
  updateItem(enc: { id: string; vault_id: string; key: string; data: string }, item: unknown) {
    this.check(enc);
    const rev = Math.max(revOf(JSON.parse(enc.data)), revOf(item)) + 1;
    return { ...enc, data: JSON.stringify({ ...(item as object), rev }) };
  }
}

/** A signing identity that is simply this account's. */
class FakeSigning {
  free() {}
  identityHash() {
    return `identity-of-${control.userId}`;
  }
  publicIdentity() {
    return { user_id: control.userId, public_key: "fake-public-key", signing_key: "fake-signing-key", identity_signature: "sig", x25519_signature: "sig" };
  }
  fingerprint() {
    return "AAAA BBBB CCCC DDDD";
  }
}

export class FakeAccount {
  free() {}
  /** Signed sharing: any listed identity record opens; a new one is a record naming the account. Key pins are JSON. */
  openSigningIdentity(_record: unknown) {
    return new FakeSigning();
  }
  newSigningIdentity() {
    return { record: { user_id: control.userId, fake_identity: true }, takeIdentity: () => new FakeSigning(), free() {} };
  }
  openKeyPins(sealed: string) {
    return JSON.parse(sealed);
  }
  sealKeyPins(pins: unknown) {
    return JSON.stringify(pins);
  }
  toSessionBytes() {
    return new Uint8Array([1, 2, 3]);
  }
  /**
   * Approving a sign-in from another device (the core's rule: the words picked must be the request key's, else
   * `phrase_mismatch`): what was sealed to whom is visible in the "box", and a fixed code.
   */
  approveLoginRequest(publicKey: string, requestId: string, chosenPhrase: string, secretKey?: string | null) {
    if (chosenPhrase !== realLoginPhrase(publicKey)) throw new Error("phrase_mismatch");
    return { sealed: `sealed(${publicKey},${requestId},${secretKey ?? "-"})`, code: "123456" };
  }
  openLoginChallenge(challenge: string, requestId: string) {
    return `proof(${challenge},${requestId})`;
  }
  openVaultKey(_id: string, wrapped: string, _kind: string, _keyEpoch?: number, _legacyAllowed?: boolean) {
    return new FakeVaultKey(wrapped);
  }
  /** Like the core's check that a bundle is this account's: false only for a bundle of `control.foreignAccountId`. */
  matchesBundle(bundle: { account_id?: unknown } | null | undefined) {
    return !!bundle && bundle.account_id !== control.foreignAccountId;
  }
  /** Like the core's avatar sealing: `sealed:<base64>`; anything else doesn't open (`decrypt_failed`). */
  sealAvatar(image: Uint8Array) {
    if (!image.length) throw new Error("invalid_input");
    let t = "";
    for (const b of image) t += String.fromCharCode(b);
    return `sealed:${btoa(t)}`;
  }
  openAvatar(sealed: string) {
    if (!sealed.startsWith("sealed:")) throw new Error("decrypt_failed");
    return Uint8Array.from(atob(sealed.slice(7)), (c) => c.charCodeAt(0));
  }
  /** The account's own identity: what the background reads as "me" (the account id the core authenticated). */
  legacyIdentity() {
    return { user_id: control.userId, public_key: "fake-public-key", signing_key: null, identity_signature: null, x25519_signature: null };
  }
  /** Like the core: the same keys in a bundle that opens with `password` (a new "salt" each time), no Secret Key. */
  rewrap(bundle: Record<string, unknown>, password: string, withSecretKey: boolean) {
    control.rewrapped++;
    const fresh = { ...bundle, password, secret_key: undefined, secret_key_enabled: withSecretKey, kdf: { salt: `salt-${++seq}` } };
    return { bundle: fresh, free() {}, takeAccount: () => new FakeAccount(), takeMaster: () => ({ free() {} }) };
  }
}

/** Bundles open with `bundle.password` (and `bundle.secret_key` when set). */
class FakeMaster {
  constructor(
    private password: string,
    private secretKey: string | null | undefined,
  ) {}
  free() {}
  unlock(bundle: { password?: string; secret_key?: string }) {
    if (bundle.password !== this.password || (bundle.secret_key && bundle.secret_key !== this.secretKey)) throw new Error("decrypt_failed");
    return new FakeAccount();
  }
}

let realLoginPhrase: (publicKey: string) => string = () => "";

/** The real core's functions that don't touch keys: the worker's site logic runs on them, as in the extension. */
async function realSiteLogic() {
  await loadManifests();
  const real = await vi.importActual<typeof Core>("../src/wasm/passauth_core");
  real.initSync({ module: readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/wasm/passauth_core_bg.wasm")) });
  realLoginPhrase = real.loginPhrase;
  const {
    normalizeHost,
    publicSuffix,
    registrableDomain,
    isPublicSuffix,
    baseDomain,
    publicSuffixListVersion,
    matchesUrl,
    matchUrls,
    downgrade,
    regexError,
    planSave,
    chosenSaveTarget,
    passkeySaveTargets,
    passkeyDefaultTarget,
    effectiveRpId,
    loginPhrase,
    loginPhraseChoices,
    itemRevCheck,
    manifestDataHash,
    normalizeEmail,
  } = real;
  return {
    normalizeHost,
    publicSuffix,
    registrableDomain,
    isPublicSuffix,
    baseDomain,
    publicSuffixListVersion,
    matchesUrl,
    matchUrls,
    downgrade,
    regexError,
    planSave,
    chosenSaveTarget,
    passkeySaveTargets,
    passkeyDefaultTarget,
    effectiveRpId,
    loginPhrase,
    loginPhraseChoices,
    itemRevCheck,
    manifestDataHash,
    normalizeEmail,
  };
}

/** Signed sharing that finds nothing wrong and pins nothing (see the file comment). */
const signedSharingStandIn = {
  verifyIdentity: (identity: { user_id?: string }) => ({ hash: `identity-of-${identity?.user_id ?? ""}`, fingerprint: "AAAA BBBB CCCC DDDD" }),
  pinsCheckOwnIdentity: () => "same",
  pinsSetOwnIdentity: (pins: unknown) => pins,
  pinsGrandfather: (pins: unknown) => pins,
  pinsLeave: (pins: unknown) => pins,
  pinsLegacyWrapAllowed: () => true,
  accountWrapIsBound: () => false,
  rosterHead: () => ({ status: "none" }),
  pinsObserve: (pins: unknown) => ({ admission: { status: "ok", trust: "signed" }, pins }),
};

export async function module() {
  // Every fake server of this test file lists a signing identity the stand-in account opens.
  defaults.identity = { user_id: control.userId, fake_identity: true };
  return {
    ...(await realSiteLogic()),
    ...signedSharingStandIn,
    default: vi.fn(() => control.init()),
    accountFromSessionBytes: vi.fn(() => {
      control.restored++;
      return new FakeAccount();
    }),
    deriveMasterKeys: vi.fn((password: string, secretKey: string | null | undefined) => new FakeMaster(password, secretKey)),
    opaqueLoginStart: vi.fn(() => ({ message: "start", state: new Uint8Array([0]) })),
    opaqueLoginFinish: vi.fn(() => "finish"),
    newId: () => crypto.randomUUID(),
    totpCode: (_secret: string, t: number) => ({ code: "123456", remaining: 30 - (Math.floor(t) % 30), period: 30 }),
    estimateBits: () => 80,
    generatePassword: () => "generated-password",
    generatePassphrase: () => "generated passphrase",
  };
}
