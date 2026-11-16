/**
 * Tests only: load the real core (WASM) and `testdata/vectors.json` in Vitest (Node). Node modules are imported by a
 * name held in a variable, so the app's type check (browser types only) doesn't need Node's.
 */
import * as core from "../wasm/passauth_core";

const nodeFs = "node:fs";

async function readBytes(rel: string): Promise<Uint8Array> {
  const { readFileSync } = (await import(/* @vite-ignore */ nodeFs)) as { readFileSync: (p: URL) => Uint8Array };
  return readFileSync(new URL(rel, import.meta.url));
}

let ready: Promise<void> | null = null;

/** Initialise the core once per test file. */
export function loadCore(): Promise<void> {
  ready ??= readBytes("../wasm/passauth_core_bg.wasm").then((bytes) => {
    core.initSync({ module: bytes as BufferSource });
  });
  return ready;
}

/** The `signedSharing` section of the shared test vectors. */
export async function signedVectors(): Promise<SignedVectors> {
  const text = new TextDecoder().decode(await readBytes("../../../testdata/vectors.json"));
  return (JSON.parse(text) as { signedSharing: SignedVectors }).signedSharing;
}

export function unb64(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

type Id = { user_id: string; public_key: string; signing_key: string | null; identity_signature: string | null; x25519_signature: string | null };
type Outcome = { expected?: unknown; error?: string };
/** A member in the vectors: [name, role, legacy?, email?] (rogue rosters may hold other values). */
export type VectorMember = [string, string, boolean?, (string | boolean)?] | string;

export interface SignedVectors {
  accounts: { name: string; id: string; sessionBytes: string; record: core.IdentityRecord }[];
  vault: { id: string; wrappedKey: string; wrappedKeyV2: string; secondKeyV2: string };
  openings: ({ wrap: string; keyEpoch: number; legacyAllowed: boolean } & Outcome)[];
  keyIds: { first: string; second: string };
  identities: { name: string; publicIdentity: Id; legacyIdentity: Id; statement: string; hash: string; legacyHash: string; fingerprint: string }[];
  forgedUpgrade: Id;
  shares: { signer: string; recipient: string; recipientLegacy: boolean; vaultId: string; role: string; keyEpoch: number; sealedKey: string; signature: string }[];
  rosters: { name: string; signer: string; previous: string | null; version: number; keyEpoch: number; members: VectorMember[]; rogue: boolean; json: string; hash: string }[];
  commitments: { keyEpoch: number; commitment: string }[];
  chains: ({ vault: string; trusted: string | null; newer: string[]; latest: string } & Outcome)[];
  heads: ({ vault: string; remembered: string | null; latest: string | null } & Outcome)[];
  memberDiffs: { roster: string; members: VectorMember[]; expected: unknown }[];
  rosterRoles: { roster: string; identity: [string, boolean]; member: string | null; signer: string | null }[];
  keyPins: core.KeyPins;
  pinChecks: { identity: [string, boolean]; email: string | null; expected: string }[];
  reviews: { name: string; previous: string | null; signer: string; members: VectorMember[]; expected: core.RosterReview }[];
  epochChecks: { pinned: core.EpochPin | null; current: core.EpochPin; expected: string }[];
  keyPinsWithEpoch: core.KeyPins;
  pinsEpochChecks: { current: core.EpochPin; rosterVersion: number | null; expected: string }[];
  keyPinsRaised: core.KeyPins;
  mergedEpochs: Record<string, core.EpochPin>;
  keyPinsLeft: core.KeyPins;
  keyPinsGrandfathered: core.KeyPins;
  keyPinsWithheld: core.KeyPins;
  keyPinsUnsigned: core.KeyPins;
  keyPinsRosterMax: core.KeyPins;
  admissions: { pins: string; observation: core.VaultObservation; expected: core.Admission }[];
  observations: { observation: core.VaultObservation; expected: core.Observed }[];
  emails: { email: string; expected: string }[];
  legacyWraps: { pins: string; expected: boolean }[];
  ownIdentity: { hash: string; pins: core.KeyPins; checks: { pins: string; listed: string | null; expected: string }[] };
}

/** The vector accounts, opened from their session bytes. */
export function vectorAccounts(v: SignedVectors): Map<string, { id: string; account: core.Account; record: core.IdentityRecord }> {
  return new Map(v.accounts.map((a) => [a.name, { id: a.id, account: core.accountFromSessionBytes(a.id, unb64(a.sessionBytes)), record: a.record }]));
}
