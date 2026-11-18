/**
 * A stand-in for the WASM core (crates/core-wasm) with the crypto surface the
 * background uses. "Encryption" is JSON plus a tag naming the vault key that
 * wrapped the item key, so an item encrypted under a replaced vault key fails
 * to open, as with the real core. The site logic (host names, matching, the save
 * rule, passkey targets, RP IDs, sign-in phrases) is the real core's. Used through
 *   vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module())
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { vi } from "vitest";
import type * as Core from "../src/wasm/passauth_core";

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

export class FakeVaultKey {
  constructor(public tag: string) {}
  free() {}
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
  encryptItem(item: unknown, id: string, vault_id: string) {
    return { id, vault_id, key: `${this.tag}:${++seq}`, data: JSON.stringify(item) };
  }
  updateItem(enc: { id: string; vault_id: string; key: string; data: string }, item: unknown) {
    this.check(enc);
    return { ...enc, data: JSON.stringify(item) };
  }
}

export class FakeAccount {
  free() {}
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
  };
}

export async function module() {
  return {
    ...(await realSiteLogic()),
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
