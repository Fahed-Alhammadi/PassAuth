/**
 * The server admin's account policies (servers with the `policies` feature; rules shared with the web vault in
 * `@web/lib/policies`):
 * - 403 `two_step_required` (the server requires two-step login and the account has no method yet): remembered per
 *   account in session storage (`twoStep:<account>`) until a sync or revision check gets through again; the popup
 *   then shows "Your server requires two-step login" instead of the vault.
 * - `max_vault_timeout_minutes`: the longest vault timeout. The setting is shared by every account, so the shortest
 *   limit of the signed-in accounts' servers applies; a saved choice above it ("Never", "On browser restart" and "On
 *   system lock" are above every limit) is lowered to it, and Settings says so (`timeoutLowered`).
 * - `GET /account` `policy_violations`: what the account still has to change, shown as a dismissible notice in the
 *   popup that links to the web vault (kept 10 minutes per account, `violations:<account>`).
 */
import type { PublicConfig } from "@web/lib/api";
import { policyNotices, readPolicies, readViolations, timeoutWithin, violationsKey } from "@web/lib/policies";
import { logged } from "../shared/log";
import type { PolicyNotices, PopupState, VaultTimeout } from "../shared/types";
import { api, serverInfo } from "./api";
import { local, scratch } from "./storage";

const twoStepKey = (id: string) => `twoStep:${id}`;
const violationsStoreKey = (id: string) => `violations:${id}`;
/** chrome.storage.local: the vault timeout a policy replaced (`{ from }`), until the user picks one again. */
export const TIMEOUT_LOWERED_KEY = "timeoutLowered";

/** Accounts known (in this worker) to have no two-step flag: no storage call on every sync for them. */
const clear = new Set<string>();

/** The server refused a request with 403 `two_step_required` for `id` (api.ts calls this before it throws). */
export async function noteTwoStepRequired(id: string) {
  clear.delete(id);
  await scratch.set(twoStepKey(id), true).catch(logged("Noting the two-step requirement"));
}

/** A sync or revision check for `id` got through: whatever two-step setup the server asked for is done. */
export async function noteTwoStepDone(id: string) {
  if (!id || clear.has(id)) return;
  clear.add(id);
  await scratch.remove(twoStepKey(id)).catch(logged("Clearing the two-step requirement"));
}

/** Sign-out or a lost session: the account's policy state goes. */
export async function forgetPolicyState(ids: string[]) {
  for (const id of ids) clear.delete(id);
  await scratch.remove(ids.flatMap((id) => [twoStepKey(id), violationsStoreKey(id)]));
}

/** The policies of `server` (`@web/lib/policies` `Policies`), from its cached `/api/config`; the defaults while unknown. */
async function policiesOf(server: string) {
  const info = await serverInfo(server);
  return readPolicies(info ? ({ policies: info.policies } as PublicConfig) : null);
}

/** The longest vault timeout the signed-in accounts' servers allow, in minutes (0 = no limit). */
export async function timeoutLimit(): Promise<number> {
  const { accounts } = await local.get();
  const servers = [...new Set(Object.values(accounts).flatMap((a) => (a.server && a.tokens ? [a.server] : [])))];
  let limit = 0;
  for (const server of servers) {
    const max = (await policiesOf(server)).maxVaultTimeoutMinutes;
    if (max > 0) limit = limit ? Math.min(limit, max) : max;
  }
  return limit;
}

/**
 * Lower a saved vault timeout above the servers' limit to the limit (and remember what it was, for Settings). True
 * when it changed: the caller restarts the timer and drops keys kept on disk for "Never".
 */
export async function enforceTimeoutPolicy(): Promise<boolean> {
  const limit = await timeoutLimit();
  if (!limit) return false;
  let from: VaultTimeout | null = null;
  await local.update((l) => {
    if (timeoutWithin(l.settings.vaultTimeout, limit)) return null;
    from = l.settings.vaultTimeout;
    return { settings: { ...l.settings, vaultTimeout: limit } };
  });
  if (from === null) return false;
  await chrome.storage.local.set({ [TIMEOUT_LOWERED_KEY]: { from } });
  return true;
}

/** A timeout the user picks: within the limit (a value above it, e.g. from an older popup, becomes the limit). */
export async function allowedTimeout(value: VaultTimeout): Promise<VaultTimeout> {
  const limit = await timeoutLimit();
  return limit && !timeoutWithin(value, limit) ? limit : value;
}

/** What the popup's state carries about policies for the active account `id`. */
export async function policyState(id: string): Promise<Pick<PopupState, "twoStepRequired" | "timeoutLimit" | "timeoutLowered">> {
  const [flag, limit, lowered] = await Promise.all([
    scratch.get<boolean>(twoStepKey(id)),
    timeoutLimit(),
    chrome.storage.local.get(TIMEOUT_LOWERED_KEY).then((r) => r[TIMEOUT_LOWERED_KEY] as { from?: VaultTimeout } | undefined),
  ]);
  return {
    ...(flag === true ? { twoStepRequired: true } : {}),
    ...(limit ? { timeoutLimit: limit } : {}),
    ...(limit && lowered?.from !== undefined ? { timeoutLowered: lowered.from } : {}),
  };
}

const VIOLATIONS_MS = 10 * 60_000;

/**
 * The active account's policy notices (`GET /account` `policy_violations`, servers with the `policies` feature),
 * each linking to the place in the web vault that fixes it. Asked again after 10 minutes; nothing on failure.
 */
export async function accountNotices(): Promise<PolicyNotices> {
  const none: PolicyNotices = { key: "", notices: [] };
  const { id, data } = await local.account();
  if (!id || !data?.server || !data.tokens) return none;
  const info = await serverInfo(data.server);
  if (!info) return none;
  let stored = await scratch.get<{ at: number; list: unknown }>(violationsStoreKey(id));
  const now = Date.now();
  if (!stored || typeof stored.at !== "number" || now - stored.at > VIOLATIONS_MS || now < stored.at) {
    const account = await api<{ policy_violations?: unknown }>("/account", { accountId: id }).catch(() => null);
    if (!account) return none;
    stored = { at: now, list: account.policy_violations ?? [] };
    await scratch.set(violationsStoreKey(id), stored);
  }
  const violations = readViolations(stored.list);
  if (!violations.length) return none;
  const notices = policyNotices(violations, readPolicies({ policies: info.policies } as PublicConfig)).map((n) => ({
    text: n.text,
    ...(n.action ? { url: `${data.server}${n.action.to}`, label: n.action.label } : {}),
  }));
  return { key: `${id}|${violationsKey(violations)}`, notices };
}
