/**
 * "Sign in with another device", the new device's side (servers with `login_with_device`; docs/ARCHITECTURE.md
 * "Approve a sign-in from another device"). The request's key can't be saved, so the request runs in the popup page
 * that made it (popup/device-sign-in.tsx, the web vault's state machine `runDeviceLogin`): only that page ever holds
 * the key, shows its words and opens the approval. The worker is its transport to the account's server, pinned to the
 * account the request was made for (`account`), and finishes the sign-in like a password one (vault.ts
 * `finishDeviceSignIn`). The access code goes in a header (`X-PassAuth-Access-Code`), never in the URL.
 */
import { ACCESS_CODE_HEADER, type NewRequestBody, type PollOutcome } from "@web/lib/device-login";
import type { LoginFinishResponse } from "@web/lib/types";
import { AppError, EXPIRED, UNREACHABLE } from "../shared/errors";
import type { DeviceSignInStart } from "../shared/types";
import { ApiError, api, logoutRemote } from "./api";
import { accountKey, local } from "./storage";
import * as vault from "./vault";

/** The account a request is made for: the active one, signed out, with a server. */
async function signedOut(account: string): Promise<{ server: string }> {
  const l = await local.get();
  if (!account || l.activeId !== account || !l.server) throw new AppError(EXPIRED, "PassAuth switched accounts while you signed in. Start again.");
  if (l.tokens) throw new AppError(EXPIRED, "This account is signed in already.");
  return { server: l.server };
}

/** What starting a request needs: the account it is for, and how this browser names itself (and its two-step pass for `email`). */
export async function startDeviceSignIn(email: string): Promise<DeviceSignInStart> {
  const l = await local.get();
  const account = l.activeId;
  await signedOut(account);
  return { account, device: await vault.deviceInfo(), rememberToken: l.rememberTokens[accountKey(l.server, email)] ?? null };
}

/**
 * `POST /auth/requests`: the request as the popup made it (its public key, the access code it keeps), with this
 * browser's own device and "remember this browser" token for that email filled in here.
 */
export async function createDeviceRequest(account: string, body: NewRequestBody): Promise<unknown> {
  const { server } = await signedOut(account);
  const l = await local.get();
  const device = await vault.deviceInfo();
  const remember = l.rememberTokens[accountKey(server, body.email)];
  const request: NewRequestBody = {
    email: body.email,
    public_key: body.public_key,
    access_code: body.access_code,
    device_id: device.id,
    device_name: device.name,
    device_kind: device.kind,
    ...(remember ? { remember_token: remember } : {}),
  };
  return api("/auth/requests", { body: request, auth: false, accountId: account });
}

/** `GET /auth/requests/{id}` with the access code, sorted into what the request's run does next (as the web vault does). */
export async function pollDeviceRequest(account: string, id: string, accessCode: string): Promise<PollOutcome> {
  await signedOut(account);
  try {
    return { kind: "answer", body: await api<unknown>(`/auth/requests/${encodeURIComponent(id)}`, { auth: false, headers: { [ACCESS_CODE_HEADER]: accessCode }, accountId: account }) };
  } catch (e) {
    // Unknown id or code: the server deleted the request a day after it expired.
    if (e instanceof ApiError && e.status === 404) return { kind: "gone" };
    if (e instanceof AppError && e.code === UNREACHABLE) return { kind: "retry" };
    if (e instanceof ApiError && (e.status === 429 || e.status >= 500)) return { kind: "retry", ...(e.retryAfter !== undefined ? { afterMs: e.retryAfter * 1000 } : {}) };
    throw e;
  }
}

/** Two-step login after an approval: the session (with the sealed key) for the popup to open, or the server's refusal. */
export async function verifyDeviceTwoStep(account: string, token: string, provider: string, code: string, remember: boolean): Promise<LoginFinishResponse> {
  await signedOut(account);
  return api<LoginFinishResponse>("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false, accountId: account });
}

/** A session that arrived but won't be used (the run was cancelled, or the approval didn't open): signed out again, best effort. */
export async function discardDeviceSession(account: string, accessToken: string): Promise<void> {
  const { server } = (await local.account(account)).data ?? { server: "" };
  await logoutRemote(server ?? "", { access: accessToken });
}
