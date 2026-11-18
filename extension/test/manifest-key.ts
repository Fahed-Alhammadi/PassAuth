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
  link: string | null;
  live: number;
  trashed: number;
}

/** What the builders answer: what to send (`seq`, `prev`, `sealed`) and the manifest's own link. */
export interface Written {
  seq: number;
  prev: string;
  sealed: string;
  link: string;
}

/** The manifest methods of the vault key named `tag` (the real core's signatures). */
export function manifestKey(tag: string) {
  const id = (vaultId: string) => `${vaultId}|${tag}`;
  return {
    manifestVerify: (
      vaultId: string,
      epoch: number,
      seq: number,
      prev: string | null | undefined,
      sealed: string | null | undefined,
      rememberedVersion: number | null | undefined,
      rememberedLink: string | null | undefined,
      log: unknown,
      items: unknown,
    ): Check => realKey().manifestVerify(id(vaultId), epoch, seq, prev, sealed, rememberedVersion, rememberedLink, log, items),
    manifestAccept: (vaultId: string, epoch: number, seq: number, prev: string | null | undefined, sealed: string | null | undefined, items: unknown): Check =>
      realKey().manifestAccept(id(vaultId), epoch, seq, prev, sealed, items),
    manifestStart: (vaultId: string, epoch: number, version: number, prev: string | null | undefined, items: unknown): Written => realKey().manifestStart(id(vaultId), epoch, version, prev, items),
    manifestNext: (vaultId: string, epoch: number, seq: number, prev: string, sealed: string, removed: unknown, added: unknown): Written =>
      realKey().manifestNext(id(vaultId), epoch, seq, prev, sealed, removed, added),
  };
}

/** The link of a vault row's manifest (the core's `manifestLink`). */
export function manifestLink(seq: number, prev: string, sealed: string): string {
  if (!real) throw new Error("await loadManifests() first");
  return real.manifestLink(seq, prev, sealed);
}

/** The predecessor a vault's first manifest names: 32 zero bytes. */
export const ZERO_LINK = "A".repeat(43);

/** The core's hash of an item's data text (`data_sha256`). */
export function dataHash(data: string): string {
  if (!real) throw new Error("await loadManifests() first");
  return real.manifestDataHash(data);
}
