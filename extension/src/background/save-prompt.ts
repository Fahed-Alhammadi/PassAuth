/**
 * Offering to save what the user typed into a login form (the save rule is the core's: site.ts `planSave`). The prompt is an
 * extension page in a frame the content script places in the top-right corner of the page (like the inline menu),
 * so the website can read neither the logins listed in it nor what the user picks. The pending save's nonce ties
 * the frame to the tab; the first frame to use it owns it (nonces.ts).
 *
 * When the prompt shows: after a page load the background shows it itself (`onTabUpdated`; content scripts don't
 * ask on every load), and in single-page apps when the submitted form goes away (page:formDone). It takes the
 * keyboard focus only after a keyboard submit. A password PassAuth generated ("Use a strong password", inline
 * menu) is kept as a pending save from the moment it is filled (`rememberGenerated`, 10 minutes), so its prompt
 * follows the sign-up even when PassAuth doesn't see the submit.
 */

import { siteHost } from "@web/lib/types";
import { AppError, codeOf, EXPIRED, INSUFFICIENT_STORAGE, messageOf, notAllowed, QUOTA_EXCEEDED } from "../shared/errors";
import { credentialsFit, MAX_USERNAME } from "../shared/limits";
import { log, logged, loggedAs } from "../shared/log";
import { hostText, pageText } from "../shared/page-text";
import { clampPromptHeight, promptHeight } from "../shared/save-layout";
import type { AddSiteTarget, SaveAnswer, SaveDetails, SaveEdits, SaveOffer, SavePrompt } from "../shared/types";
import { touch } from "./activity";
import { siteOrigin, withSite } from "./add-site";
import { QUOTA_TEXT, STORAGE_TEXT } from "./api";
import { initCore } from "./core";
import { matching } from "./matching";
import { forgetNonce, ownsNonce, thisFrame } from "./nonces";
import { type Expiring, store } from "./pending";
import { sameSiteAsTab, senderUrl } from "./senders";
import { applyToLogin, baseDomain, chosenTarget, NEW_LOGIN, parse, planSave, type SaveTarget } from "./site";
import { webFrame } from "./sites";
import { getSettings, local } from "./storage";
import { type FrameTarget, TOP_FRAME, toTab, toTabQuietly } from "./tabs";
import { notifyTab } from "./toast";
import * as vault from "./vault";

type Sender = chrome.runtime.MessageSender;

interface PendingSave extends Expiring {
  /** The account that was active when this was typed: it is never saved into another account's vault. */
  accountId: string;
  url: string;
  username: string;
  password: string;
  /** Preselected under "Save in": the login to update, or `NEW_LOGIN`. */
  target: string;
  /** The logins the user may pick instead (their own ones for this site, and shared ones under the typed user name; the save rule). */
  targets: SaveTarget[];
  /** Nothing saved for this site: own logins for other sites with the same user name and password ("add this site to"). */
  addTo?: AddSiteTarget[];
  /** Ties the prompt the user sees to this pending save. */
  nonce: string;
  /** The prompt frame that used the nonce first: the only one that may answer. */
  frame?: FrameTarget;
  /** Id of the new login, kept so that "Save" after a failed try can't create two. */
  itemId: string;
  /** Submitted from the keyboard: the prompt takes the focus. */
  keyboard?: boolean;
  /** A password PassAuth generated for this page: kept longer, and its prompt doesn't go away by itself. */
  generated?: boolean;
}

/** How long a typed login waits for the user's answer, and a generated password (a sign-up takes longer). */
const SAVE_MS = 120_000;
const GENERATED_MS = 10 * 60_000;

/** One record per tab (`save:<tabId>`), and the user name typed on the first step of an identifier-first login (`user:<tabId>`). */
const saves = store<PendingSave>("save:");
const lastUsers = store<{ site: string; username: string } & Expiring>("user:");

const closePrompt = (tabId: number) => toTabQuietly(tabId, { type: "save:close" }, TOP_FRAME);

/** Lock, sign-out, account switch: what was typed and not yet saved is forgotten, and open prompts close. */
export async function dropSaves() {
  for (const tabId of await saves.clear()) void closePrompt(Number(tabId));
}

/** A tab closed: its pending save and identifier-first user name go. */
export async function forgetTab(tabId: number) {
  await saves.remove(tabId);
  await lastUsers.remove(tabId);
}

/** The user name typed on the first step of an identifier-first login (page:identifier). */
export async function rememberUser(sender: Sender, username: string) {
  const frame = webFrame(sender);
  const tabId = sender.tab?.id;
  const host = senderUrl(frame)?.hostname;
  if (tabId === undefined || !host || !username || username.length > MAX_USERNAME || !sameSiteAsTab(frame)) return;
  await lastUsers.put(tabId, { site: baseDomain(host), username, expires: Date.now() + 10 * 60_000 });
}

const MAX_SAVE_TARGETS = 12;

/** The default target and the "Save in" choices for what was typed (the save rule, site.ts), or null when there is nothing to offer. */
async function planFor(url: string, username: string, password: string): Promise<Pick<PendingSave, "target" | "targets" | "addTo"> | null> {
  const host = parse(url)?.hostname ?? "";
  const candidates = (await matching(url)).flatMap((e) => {
    const login = e.item.login;
    if (!login) return [];
    return [
      {
        id: e.id,
        name: (e.item.name || host).slice(0, 120),
        username: login.username,
        password: login.password,
        writable: vault.canWrite(e),
        personal: vault.isPersonal(e),
        vault: vault.vaultName(e.vaultId).slice(0, 60),
      },
    ];
  });
  const plan = planSave(candidates, username, password);
  if (plan.action === "none") return null;
  // The prompt lists a handful; the preselected login is always among them.
  const targets = [...plan.targets.filter((t) => t.id === plan.target), ...plan.targets.filter((t) => t.id !== plan.target)]
    .slice(0, MAX_SAVE_TARGETS)
    .map((t) => ({ ...t, username: t.username.slice(0, 256) }));
  const addTo = targets.length ? [] : sameAccountElsewhere(username, password);
  return { target: plan.target, targets, ...(addTo.length ? { addTo } : {}) };
}

const MAX_ADD_TO = 3;

/**
 * The user's own logins (for other sites: nothing matched this one) saved with exactly this user name and password:
 * the same account, used on one more site. Both must be typed; a password alone says nothing about the account.
 */
function sameAccountElsewhere(username: string, password: string): AddSiteTarget[] {
  const user = username.trim().toLowerCase();
  if (!user || !password) return [];
  return vault
    .allEntries()
    .filter((e) => e.item.login && vault.isPersonal(e) && vault.canWrite(e) && e.item.login.password === password && e.item.login.username.trim().toLowerCase() === user)
    .slice(0, MAX_ADD_TO)
    .map((e) => {
      const site = siteHost(e.item).replace(/^www\./, "");
      return { id: e.id, name: (e.item.name || site || "Login").slice(0, 120), username: e.item.login!.username.slice(0, 256), site: site.slice(0, 120) };
    });
}

/**
 * The page submitted a login form (page:submitted): keep what was typed for the prompt, if there is something to
 * offer. Page-supplied: at most 1 KiB of user name and 4 KiB of password; anything longer isn't offered at all.
 */
export async function onSubmitted(sender: Sender, username: string, password: string, keyboard = false): Promise<boolean> {
  const frame = webFrame(sender);
  const tabId = sender.tab?.id;
  const page = senderUrl(frame);
  if (tabId === undefined || !page || !credentialsFit(username, password) || !sameSiteAsTab(frame)) return false;
  if (!(await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault for a save")))) return false;
  const host = page.hostname;
  const { neverSave, settings, activeId } = await local.get();
  if (!settings.askToSave || !host || neverSave.includes(baseDomain(host))) return false;
  let user = username;
  if (!user) {
    // Identifier-first logins ask for the password on a second step without the username field.
    const last = await lastUsers.get(tabId);
    if (last && last.site === baseDomain(host)) user = last.username;
  }
  user = user.trim();
  // Update a login the vault already has for this site instead of saving a second one.
  const plan = await planFor(page.href, user, password);
  if (!plan) return false;
  // The submit of a generated password: its save keeps the longer wait.
  const before = await saves.get(tabId);
  const generated = !!before?.generated && before.password === password;
  await saves.put(tabId, {
    accountId: activeId,
    url: page.href,
    username: user,
    password,
    ...plan,
    nonce: crypto.randomUUID(),
    itemId: crypto.randomUUID(),
    expires: generated && before ? Math.max(before.expires, Date.now() + SAVE_MS) : Date.now() + SAVE_MS,
    ...(keyboard ? { keyboard: true } : {}),
    ...(generated ? { generated: true } : {}),
  });
  return true;
}

/**
 * "Use a strong password" filled `password` into a sign-up form at `url` (inline-menu.ts): keep it as a pending save
 * for the tab, so the prompt follows the sign-up (a later submit of the form replaces it with what was typed).
 * Kept even when "Ask to save" is off or the site is on the never-save list: a generated password nobody saved is lost.
 */
export async function rememberGenerated(tabId: number, url: string, username: string, password: string) {
  const page = parse(url);
  if (!page || !credentialsFit(username, password)) return;
  let user = username.trim();
  if (!user) {
    const last = await lastUsers.get(tabId);
    if (last && last.site === baseDomain(page.hostname)) user = last.username;
  }
  const plan = await planFor(page.href, user, password);
  if (!plan) return;
  const { activeId } = await local.get();
  await saves.put(tabId, {
    accountId: activeId,
    url: page.href,
    username: user,
    password,
    ...plan,
    nonce: crypto.randomUUID(),
    itemId: crypto.randomUUID(),
    expires: Date.now() + GENERATED_MS,
    generated: true,
  });
}

/** What the page side gets: the nonce for the prompt frame, a first height for it and whether it takes the focus. Nothing from the vault. */
const promptOf = (p: PendingSave): SavePrompt => ({ nonce: p.nonce, height: promptHeight(p.targets.length + (p.addTo?.length ?? 0)), ...(p.keyboard ? { focus: true } : {}) });

/** What the prompt frame shows. */
async function offerOf(p: PendingSave): Promise<SaveOffer> {
  const { theme } = await getSettings();
  return {
    host: parse(p.url)?.hostname ?? "",
    username: p.username,
    targets: p.targets,
    ...(p.addTo?.length ? { addTo: p.addTo } : {}),
    selected: p.target,
    theme,
    ...(p.generated ? { generated: true } : {}),
  };
}

/**
 * The pending save of tab `tabId`, if it belongs to the account that is active now and the tab's top page
 * (`tabUrl`) is still on the site the login was typed on.
 */
async function pendingFor(tabId: number | undefined, tabUrl: string | undefined): Promise<PendingSave | undefined> {
  if (tabId === undefined) return undefined;
  const p = await saves.get(tabId);
  if (!p) return undefined;
  // Typed under another account (or stored by an older version of the extension): gone, not carried over.
  if (!p.accountId || p.accountId !== (await local.get()).activeId || !Array.isArray(p.targets) || typeof p.target !== "string" || typeof p.itemId !== "string") {
    await saves.remove(tabId);
    return undefined;
  }
  const top = parse(tabUrl ?? "")?.hostname ?? "";
  return top && baseDomain(top) === baseDomain(parse(p.url)?.hostname ?? "") ? p : undefined;
}

const saveForTab = (sender: Sender) => pendingFor(sender.tab?.id, sender.tab?.url);

/** The login form went away without a page load (single-page apps, page:formDone): show the prompt in the top frame. */
export async function formDone(sender: Sender) {
  const tabId = sender.tab?.id;
  const p = sameSiteAsTab(webFrame(sender)) ? await saveForTab(sender) : undefined;
  if (tabId !== undefined && p) await toTabQuietly(tabId, { type: "showSave", ...promptOf(p) }, TOP_FRAME);
}

const withoutHash = (url: string) => url.replace(/#.*$/, "");

/**
 * A page finished loading (chrome.tabs.onUpdated, status "complete"; main.ts registers it): a pending save for its
 * tab and site is shown there, in the top frame. The content script holds it back when the page asks for a
 * password again (the sign-in most likely failed) — except for a generated password on a new page, which is
 * shown in any case (a sign-up often lands on a sign-in form). A content script that isn't there yet is asked
 * again twice, half a second apart.
 */
export async function onTabUpdated(tabId: number, change: { status?: string }, tab: { url?: string }) {
  if (change.status !== "complete" || !tab.url) return;
  await initCore();
  const p = await pendingFor(tabId, tab.url);
  if (!p) return;
  const afterLoad = !p.generated || withoutHash(tab.url) === withoutHash(p.url);
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) await new Promise((r) => setTimeout(r, 500));
    if (
      await toTab(tabId, { type: "showSave", ...promptOf(p), afterLoad }, TOP_FRAME).then(
        () => true,
        () => false,
      )
    )
      return;
  }
}

/**
 * The pending save a request from the prompt frame is about: only from a frame inside a tab's page (never the
 * prompt opened as a page of its own), with the right nonce, from the frame that owns it.
 */
async function promptSave(sender: Sender, nonce: string): Promise<{ tabId: number; p: PendingSave }> {
  const tabId = sender.tab?.id;
  if (tabId === undefined || !sender.frameId) throw notAllowed();
  const p = await saveForTab(sender);
  // A wrong or old nonce is refused and nothing else happens: whoever sent it can't close the real prompt.
  if (!p || p.nonce !== nonce) throw new AppError(EXPIRED, "This prompt has expired.");
  if (!ownsNonce(p.nonce, sender, p.frame)) throw notAllowed();
  if (!p.frame) {
    p.frame = thisFrame(sender);
    await saves.put(tabId, p);
  }
  return { tabId, p };
}

/** save:offer: what the prompt shows. */
export async function offer(sender: Sender, nonce: string): Promise<SaveOffer> {
  return offerOf((await promptSave(sender, nonce)).p);
}

/**
 * save:details: the "Edit" button. The typed login (and the name a new one gets) for the form, to the prompt frame
 * that owns the nonce only: an extension page the website can't read, like the vault logins it already lists.
 */
export async function details(sender: Sender, nonce: string): Promise<SaveDetails> {
  const { p } = await promptSave(sender, nonce);
  return { name: (parse(p.url)?.hostname ?? "").replace(/^www\./, ""), username: p.username, password: p.password };
}

/** save:resize: the prompt's content changed height (the page side learns a number, nothing else). */
export async function resize(sender: Sender, nonce: string, height: number) {
  const { tabId } = await promptSave(sender, nonce);
  await toTabQuietly(tabId, { type: "save:size", height: clampPromptHeight(height) }, TOP_FRAME);
}

/**
 * save:touch: a finger or pen touched the prompt. Sent on to the top frame's content script (the frame never posts
 * to the page itself), which then checks the prompt in every animation frame.
 */
export async function touched(sender: Sender, nonce: string) {
  const { tabId, p } = await promptSave(sender, nonce);
  await toTabQuietly(tabId, { type: "save:touch", nonce: p.nonce }, TOP_FRAME);
}

/** Saves being written right now, by nonce: a second click can't apply one twice. */
const applying = new Set<string>();

/**
 * save:answer: the user's answer in the prompt. What is applied is the target the prompt
 * displayed (`target`, which must be one this pending save offered); the
 * pending save is removed on every way out except a failure the user can retry.
 */
export async function answer(sender: Sender, nonce: string, accept: "save" | "never" | "dismiss", target: string | undefined, edits?: SaveEdits): Promise<SaveAnswer> {
  const { tabId, p: pending } = await promptSave(sender, nonce);
  // "Edit": what the user changed in the prompt replaces what was typed (for this save only; nothing is stored).
  const p: PendingSave = edits && accept === "save" ? { ...pending, username: edits.username, password: edits.password } : pending;
  const host = (parse(p.url)?.hostname ?? "").replace(/^www\./, "");
  const finish = async (saved?: "saved" | "updated"): Promise<SaveAnswer> => {
    await saves.remove(tabId);
    forgetNonce(p.nonce);
    await closePrompt(tabId);
    // Inside the page the confirmation names the site the login was typed on (the page's own address), never the vault item.
    if (saved === "updated") await notifyTab(tabId, pageText`Login updated for ${hostText(host)}.`);
    if (saved === "saved") await notifyTab(tabId, pageText`Login saved for ${hostText(host)}.`);
    return { done: true };
  };
  if (accept === "never") {
    const site = baseDomain(parse(p.url)?.hostname ?? "");
    await local.update((l) => ({ neverSave: [...new Set([...l.neverSave, site])] }));
    return finish();
  }
  if (accept !== "save") return finish();
  const addTo = typeof target === "string" ? p.addTo?.find((t) => t.id === target) : undefined;
  const choice = addTo ? addTo.id : chosenTarget(p, target);
  // Adding this site to a login changes nothing typed: the prompt offers no "Edit" for it.
  if (choice === null || (addTo && edits)) {
    await finish();
    throw notAllowed();
  }
  if (applying.has(p.nonce)) return { error: "Saving…", retry: true };
  applying.add(p.nonce);
  try {
    if (!(await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault for a save")))) {
      await saves.remove(tabId);
      return { error: "PassAuth is locked, so the login wasn't saved. Unlock PassAuth, then sign in on the site again.", retry: false };
    }
    // Saving is the user at work in PassAuth: it restarts the vault timeout.
    await touch();
    if (addTo) {
      const existing = vault.getEntry(addTo.id);
      const origin = siteOrigin(p.url);
      // Still the same account (nothing changed it since the prompt was shown); otherwise ask again.
      if (!origin || !existing?.item.login || !vault.canWrite(existing) || existing.item.login.password !== p.password) {
        const next = await planFor(pending.url, pending.username, pending.password);
        if (!next) return finish();
        const again: PendingSave = { ...pending, ...next };
        if (!next.addTo) delete again.addTo;
        await saves.put(tabId, again);
        return { again: await offerOf(again), notice: "That login changed. Check where to save, then try again." };
      }
      await vault.updateItem(existing, withSite(existing.item, origin));
      await saves.remove(tabId);
      forgetNonce(p.nonce);
      await closePrompt(tabId);
      // The page learns only that its own site was added, never which login it went to.
      await notifyTab(tabId, pageText`${hostText(host)} added to your login.`);
      return { done: true };
    }
    if (choice !== NEW_LOGIN) {
      const existing = vault.getEntry(choice);
      if (!existing?.item.login || !vault.canWrite(existing)) {
        // The login the prompt showed was removed or became read-only (a sync in between). Never save
        // somewhere the user didn't see: work the choices out again and ask again.
        const next = await planFor(pending.url, pending.username, pending.password);
        if (!next) return finish();
        const again: PendingSave = { ...pending, ...next };
        await saves.put(tabId, again);
        return { again: await offerOf(again), notice: "That login isn't in your vault any more. Check where to save, then try again." };
      }
      // updateItem moves the old password into the history; everything but the password (and a typed user name) stays.
      await vault.updateItem(existing, { ...existing.item, login: applyToLogin(existing.item.login, p.username, p.password) });
      return finish("updated");
    }
    const origin = parse(p.url)?.origin;
    if (!origin) return finish();
    // Same id on every try from this prompt: one that timed out but reached the server isn't saved twice.
    await vault.createItem(
      {
        name: edits?.name.trim() || host,
        notes: "",
        favorite: false,
        folder: null,
        tags: [],
        login: { username: p.username, password: p.password, urls: [{ url: origin, match: "default" }], totp: null, passkeys: [] },
        card: null,
        identity: null,
        ssh_key: null,
        fields: [],
        password_history: [],
        created_at: 0,
        updated_at: 0,
      },
      undefined,
      p.itemId,
    );
    return finish("saved");
  } catch (e) {
    // The pending save stays, so the user can try again from the same prompt; the reason is shown in the prompt (an extension frame), not in the page.
    log.warn("Saving a login failed:", e);
    // The server's storage limit, or its disk running out, in the words every PassAuth app uses (deleting items, then Save again, works).
    const code = codeOf(e);
    return { error: code === QUOTA_EXCEEDED ? QUOTA_TEXT : code === INSUFFICIENT_STORAGE ? STORAGE_TEXT : `PassAuth couldn't save this login. ${messageOf(e)}`, retry: true };
  } finally {
    applying.delete(p.nonce);
  }
}

/** Log a failure to drop pending saves (they expire after two minutes anyway). */
export const dropSavesLogged = () => void dropSaves().catch(logged("Dropping pending saves"));
