/**
 * Vault manifests for the tests that replace the core's crypto (test/fake-core.ts) and for the fake server
 * (test/fake-server.ts): the real core's manifest code, on the vault key of the golden vectors
 * (testdata/vectors.json `vaultManifest`). The fake core's vault keys are only names (their "tag"), so the tag is
 * mixed into the vault id the manifest is sealed for: a manifest made under another key (a replaced one) doesn't
 * open, as with real keys. Load once with `await loadManifests()` before using `manifestKey`.
 */
import { vi } from "vitest";
import type * as Core from "../src/wasm/passauth_core";
import { fromB64u } from "./helpers";

interface Fixture {
  accountId: string;
  sessionBytes: string;
  vaultId: string;
  keyEpoch: number;
  wrappedKey: string;
}

const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const fixture = (Object.values(files)[0] as { vaultManifest: Fixture }).vaultManifest;

let real: typeof Core | null = null;
let key: Core.VaultKey | null = null;

/** The real core (already initialised by test/setup.ts), also in files that mock the module. */
export async function loadManifests(): Promise<typeof Core> {
  real ??= await vi.importActual<typeof Core>("../src/wasm/passauth_core");
  return real;
}

/** Made at first use: after every `initSync` (each one starts the WASM module afresh, which would orphan the key). */
function realKey(): Core.VaultKey {
  if (!real) throw new Error("await loadManifests() first");
  key ??= real.accountFromSessionBytes(fixture.accountId, fromB64u(fixture.sessionBytes)).openVaultKey(fixture.vaultId, fixture.wrappedKey, "account", fixture.keyEpoch, false);
  return key;
}

export interface Check {
  status: string;
  version: number;
  live: number;
  trashed: number;
}

/** The manifest methods of the vault key named `tag`. */
export function manifestKey(tag: string) {
  const id = (vaultId: string) => `${vaultId}|${tag}`;
  return {
    manifestVerify: (vaultId: string, epoch: number, seq: number, sealed: string | null | undefined, remembered: number | null | undefined, items: unknown): Check =>
      realKey().manifestVerify(id(vaultId), epoch, seq, sealed, remembered, items),
    manifestStart: (vaultId: string, epoch: number, version: number, items: unknown): string => realKey().manifestStart(id(vaultId), epoch, version, items),
    manifestNext: (vaultId: string, epoch: number, seq: number, sealed: string, removed: unknown, added: unknown): { seq: number; sealed: string } =>
      realKey().manifestNext(id(vaultId), epoch, seq, sealed, removed, added),
  };
}

/** The core's hash of an item's data text (`data_sha256`). */
export function dataHash(data: string): string {
  if (!real) throw new Error("await loadManifests() first");
  return real.manifestDataHash(data);
}
