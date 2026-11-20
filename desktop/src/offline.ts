/**
 * Offline changes (web/src/lib/platform.ts `offlineChanges`): each account's change list, sealed by the web vault with
 * the account key, kept by the shell in a file per server and account (`offline_changes_*`, src-tauri/src/offline.rs).
 */
import { invoke } from "@tauri-apps/api/core";
import type { OfflineChangeStore } from "@web/lib/platform";
import { secretsHost } from "./secrets";

const name = (accountId: string) => `${secretsHost()}|${accountId}`;

export const offlineChanges: OfflineChangeStore = {
  get: (accountId) => invoke<string | null>("offline_changes_get", { name: name(accountId) }),
  set: (accountId, sealed) => invoke<void>("offline_changes_set", { name: name(accountId), value: sealed }),
};
