/**
 * Requests from PassAuth's popup page (popup.html: the toolbar popup, the pop-out window and the passkey
 * confirmation window). Extension pages are PassAuth's own code, so their messages arrive typed (no `parse`).
 */
import type { LoginUrl } from "@web/lib/types";
import { AppError, NOT_FOUND } from "../../shared/errors";
import { logged, loggedAs } from "../../shared/log";
import type { PasskeyWindowApi, PopupApi } from "../../shared/protocol";
import type { Settings } from "../../shared/types";
import { touch } from "../activity";
import { fileAccess, keptFiles, missingFiles, withoutFiles } from "../attachments";
import { copy } from "../clipboard";
import { afterUnlock, openPopup, orderedMatches } from "../commands";
import { createDeviceRequest, discardDeviceSession, pollDeviceRequest, startDeviceSignIn, verifyDeviceTwoStep } from "../device-sign-in";
import { fill } from "../fill";
import { fillProblem } from "../fill-problems";
import { markUsed } from "../last-used";
import { ensureLive } from "../live-sync";
import { decide, pendingRequest } from "../passkey-handler";
import { removePin, setPin, unlockWithPin } from "../pin";
import { accountNotices, allowedTimeout, enforceTimeoutPolicy, TIMEOUT_LOWERED_KEY } from "../policies";
import type { Handlers } from "../router";
import type { SenderKind } from "../senders";
import { answerSignIn, refreshSignInRequests, signInRequests } from "../sign-in-requests";
import { regexError } from "../site";
import { activeId, getSettings, local } from "../storage";
import * as vault from "../vault";

const POPUP: readonly SenderKind[] = ["popup"];

/**
 * The websites of a login that are used as regular expressions (match "regex", or "default" while the user's default
 * is regex) and that the core refuses, by index, with the reason: they never match.
 */
function refusedPatterns(urls: readonly LoginUrl[], defaultMatch: Settings["defaultMatch"]): Record<number, string> {
  const out: Record<number, string> = {};
  urls.forEach((u, n) => {
    const pattern = u.match === "regex" || (u.match === "default" && defaultMatch === "regex");
    const error = pattern && u.url ? regexError(u.url) : null;
    if (error) out[n] = error;
  });
  return out;
}

const entry = (id: string) => {
  const e = vault.getEntry(id);
  if (!e) throw new AppError(NOT_FOUND, "Item not found.");
  return e;
};

export const popupHandlers = {
  state: {
    from: POPUP,
    async run() {
      // The servers' longest vault timeout: a saved choice above it is lowered now (and the timer follows).
      if (await enforceTimeoutPolicy().catch(loggedAs(false, "Applying the vault timeout policy"))) {
        await vault.persistForNever();
        await touch(true);
      }
      if (await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault"))) {
        await vault.refreshIfStale().catch(logged("Checking for changes"));
        // Back to a live-sync socket if it was lost (cheap when it is up).
        void ensureLive().catch(logged("Starting live sync"));
        // Sign-ins waiting for approval (at most every 30 s; the socket says when one arrives).
        void refreshSignInRequests().catch(logged("Listing sign-in requests"));
      }
      return vault.state();
    },
  },
  setServer: { from: POPUP, run: ({ url }) => vault.setServer(url) },
  login: { from: POPUP, activity: "force", run: ({ email, password, secretKey }) => vault.login(email, password, secretKey) },
  verify2fa: { from: POPUP, activity: "force", run: ({ token, provider, code, remember }) => vault.verifyTwoFactor(token, provider, code, remember) },
  email2fa: { from: POPUP, run: ({ token }) => vault.sendTwoFactorEmail(token) },
  unlock: { from: POPUP, activity: "force", run: ({ password, secretKey }) => vault.unlock(password, secretKey) },
  // Every account, like the vault timeout.
  lock: { from: POPUP, run: () => vault.lock() },
  logout: { from: POPUP, run: () => vault.logout() },
  sync: { from: POPUP, activity: "restart", run: () => vault.sync() },
  items: {
    from: POPUP,
    unlock: true,
    async run({ url, tabId }) {
      // Suggestions: the login used last first.
      const suggested = url ? await orderedMatches(url) : [];
      const invitations = vault.invitations();
      const sharing = vault.sharingNotice();
      const problem = url && tabId !== undefined ? await fillProblem(tabId, url) : undefined;
      return {
        suggested: suggested.map(vault.summarize),
        all: vault.allEntries().map(vault.summarize),
        ...(invitations.count ? { invitations } : {}),
        ...(sharing ? { sharing } : {}),
        ...(problem ? { fillProblem: problem } : {}),
      };
    },
  },
  item: {
    from: POPUP,
    unlock: true,
    async run({ id }) {
      const e = entry(id);
      const errors = refusedPatterns(e.item.login?.urls ?? [], (await getSettings()).defaultMatch);
      return {
        item: e.item,
        vaultName: vault.vaultName(e.vaultId),
        vaultId: e.vaultId,
        ...vault.vaultTrust(e.vaultId),
        canWrite: vault.canWrite(e),
        weakPassword: vault.weakPassword(e.item.login?.password ?? ""),
        ...(Object.keys(errors).length ? { regexErrors: errors } : {}),
      };
    },
  },
  totp: {
    from: POPUP,
    unlock: true,
    run({ id }) {
      const secret = vault.getEntry(id)?.item.login?.totp;
      if (!secret) throw new AppError(NOT_FOUND, "No authenticator key.");
      // The popup counts down to `expires` itself and asks again only then.
      return vault.totp(secret);
    },
  },
  fill: { from: POPUP, activity: "restart", run: ({ id, tabId }) => fill(id, tabId) },
  generate: { from: POPUP, activity: "restart", run: ({ mode, options }) => vault.generate(mode, options) },
  // A new item lists no files; an edit keeps the file list as last synced (never the draft's): attachments.ts.
  createItem: { from: POPUP, unlock: true, activity: "restart", run: ({ item, vaultId, id }) => vault.createItem(withoutFiles(item), vaultId, id) },
  updateItem: {
    from: POPUP,
    unlock: true,
    activity: "restart",
    run({ id, item }) {
      const e = entry(id);
      return vault.updateItem(e, keptFiles(item, e.item));
    },
  },
  trashItem: { from: POPUP, unlock: true, activity: "restart", run: ({ id }) => vault.trashItem(entry(id)) },
  editorInfo: { from: POPUP, unlock: true, run: () => vault.editorInfo() },
  // The editor asks while the user types (debounced): at most 50 patterns, each checked by the core.
  settings: {
    from: POPUP,
    activity: "force",
    async run({ patch }) {
      if (patch.vaultTimeout !== undefined) {
        // A choice the servers' policies allow (the popup offers only those), and the note about a lowered one goes.
        patch = { ...patch, vaultTimeout: await allowedTimeout(patch.vaultTimeout) };
        await chrome.storage.local.remove(TIMEOUT_LOWERED_KEY);
      }
      const written = await local.update((l) => ({ settings: { ...l.settings, ...patch } }));
      // Again after saving: a new timeout length applies from now.
      await touch(true);
      await vault.persistForNever();
      return written?.settings ?? getSettings();
    },
  },
  "neverSave:remove": {
    from: POPUP,
    activity: "restart",
    async run({ domain }) {
      await local.update((l) => ({ neverSave: l.neverSave.filter((d) => d !== domain) }));
    },
  },
  copy: { from: POPUP, activity: "restart", run: ({ text }) => copy(text) },
  copyField: {
    from: POPUP,
    unlock: true,
    activity: "restart",
    async run({ id, field }) {
      const login = vault.getEntry(id)?.item.login;
      const value = field === "totp" ? (login?.totp ? vault.totp(login.totp).code : "") : (login?.[field] ?? "");
      if (!value) throw new AppError(NOT_FOUND, "Nothing to copy.");
      await copy(value);
      // Copying a login's field counts as using it (suggestions, the right-click menu and the fill shortcut put it first).
      void markUsed(await activeId(), id).catch(logged("Noting the login as used"));
    },
  },
  openPopup: { from: POPUP, run: () => openPopup() },
  "account:add": { from: POPUP, activity: "restart", run: () => vault.addAccount() },
  "account:switch": { from: POPUP, activity: "restart", run: ({ id }) => vault.switchAccount(id) },
  "account:cancelAdd": { from: POPUP, activity: "restart", run: () => vault.cancelAddAccount() },
  "account:forgetBrowser": { from: POPUP, activity: "restart", run: () => vault.forgetBrowser() },
  securityKeys: { from: POPUP, unlock: true, run: () => vault.securityKeys() },
  "securityKeys:remove": { from: POPUP, unlock: true, activity: "restart", run: ({ id, password }) => vault.removeSecurityKey(id, password) },
  "hiddenSites:remove": {
    from: POPUP,
    activity: "restart",
    async run({ domain }) {
      await local.update((l) => (l.hiddenSites.includes(domain) ? { hiddenSites: l.hiddenSites.filter((d) => d !== domain) } : null));
    },
  },
  afterUnlock: { from: POPUP, unlock: true, run: () => afterUnlock() },
  // Unlocking with a PIN is an unlock (the timer restarts at once); setting one needs the master password in the same request.
  "pin:set": { from: POPUP, unlock: true, activity: "force", run: ({ pin, password }) => setPin(pin, password) },
  "pin:unlock": { from: POPUP, activity: "force", run: ({ pin }) => unlockWithPin(pin) },
  "pin:remove": { from: POPUP, activity: "restart", run: () => removePin() },
  sharingIdentity: { from: POPUP, unlock: true, run: () => vault.sharingIdentity() },
  "sharing:trust": { from: POPUP, unlock: true, activity: "restart", run: ({ userId, fingerprint }) => vault.trustNewKey(userId, fingerprint) },
  "sharing:accept": { from: POPUP, unlock: true, activity: "restart", run: ({ vaultId, token }) => vault.acceptSharedVault(vaultId, token) },
  policyNotices: { from: POPUP, run: () => accountNotices() },
  signInRequests: { from: POPUP, unlock: true, run: () => signInRequests() },
  // Answering is the user at work in PassAuth.
  "signInRequests:answer": {
    from: POPUP,
    unlock: true,
    activity: "restart",
    run: ({ id, approve, approval }) =>
      answerSignIn(
        String(id),
        approve === true,
        approval && typeof approval.publicKey === "string" && typeof approval.challenge === "string" && typeof approval.phrase === "string" ? approval : undefined,
      ),
  },
  "deviceSignIn:start": { from: POPUP, run: ({ email }) => startDeviceSignIn(String(email)) },
  "deviceSignIn:create": { from: POPUP, run: ({ account, body }) => createDeviceRequest(account, body) },
  "deviceSignIn:poll": { from: POPUP, run: ({ account, id, accessCode }) => pollDeviceRequest(account, String(id), String(accessCode)) },
  "deviceSignIn:verify2fa": {
    from: POPUP,
    run: ({ account, token, provider, code, remember }) => verifyDeviceTwoStep(account, String(token), String(provider), String(code), remember === true),
  },
  // Signing in is an unlock: the vault timeout starts from it.
  "deviceSignIn:finish": {
    from: POPUP,
    activity: "force",
    run: ({ account, signIn, typedEmail }) => vault.finishDeviceSignIn(account, signIn, typeof typedEmail === "string" ? typedEmail : undefined),
  },
  "deviceSignIn:discard": { from: POPUP, run: ({ account, accessToken }) => discardDeviceSession(account, String(accessToken)) },
  "files:missing": { from: POPUP, unlock: true, run: ({ id }) => missingFiles(String(id)) },
  // Downloading a file is the user at work in PassAuth.
  "files:access": { from: POPUP, unlock: true, activity: "restart", run: ({ itemId, attachmentId, renew }) => fileAccess(String(itemId), String(attachmentId), renew === true) },
} satisfies Handlers<PopupApi>;

/** The passkey confirmation window (popup.html#passkey=<id>): the same page, so the same sender. */
export const passkeyWindowHandlers = {
  "passkey:pending": { from: POPUP, run: ({ requestId }) => pendingRequest(requestId) },
  "passkey:decide": {
    from: POPUP,
    activity: "restart",
    run: ({ requestId, accept, credentialId, fallback, password }) => decide(requestId, accept, credentialId, fallback, password),
  },
} satisfies Handlers<PasskeyWindowApi>;
