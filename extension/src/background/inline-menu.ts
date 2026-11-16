/**
 * The inline autofill menu. The menu is an extension page in an iframe the content script places under the field,
 * so the website can't read what it shows. A nonce ties each menu to the tab and frame that opened it
 * (`menu:<nonce>`), and to the first menu frame that uses it (nonces.ts). What the menu lists follows the field it
 * was opened on (`kind`): the logins for the page (last used first), on one-time-code fields those with a code and
 * the code itself, on card and identity fields the cards and identities. Its footer opens PassAuth at a new item
 * ("New login", `popupRoute`) and, on new-password fields, fills a generated password ("Use a strong password"),
 * which is kept as a pending save so the save prompt follows the sign-up (`fillStrongPassword`, which the right-click
 * menu's "Fill a strong password" uses too). "⋯" hides the menu on the site (sites.ts) or opens PassAuth. A fill that
 * fails leaves its reason for the popup (fill-problems.ts). A fill takes only an item the menu was given as a row
 * (`offered`). The menu frame never posts to the page: what it tells the content script that placed it (Tab or Esc:
 * focus back to the field; a finger or pen touched it) comes here with its nonce and goes on to the field's
 * document only.
 */
import { generatorRequest, PASSWORD_LENGTH } from "@web/lib/generator";
import type { Card, Identity } from "@web/lib/types";
import { AppError, CANT_FILL, EXPIRED, lockedError, notAllowed } from "../shared/errors";
import { readGeneratorSettings } from "../shared/generator-settings";
import { logged, loggedAs } from "../shared/log";
import { pageText } from "../shared/page-text";
import type { InlineOpen } from "../shared/protocol";
import { POPUP_ROUTE_KEY } from "../shared/storage-keys";
import type { InlineInfo, InlineItems, InlineKind, ItemSummary, PopupRouteRequest } from "../shared/types";
import { touch } from "./activity";
import { iconsShown } from "./api";
import { openPopup } from "./commands";
import { cardBrand, fill } from "./fill";
import { noteFillProblem } from "./fill-problems";
import { byLastUsed, lastUsedMap } from "./last-used";
import { countMatching, matching } from "./matching";
import { forgetNonce, ownsNonce, thisFrame } from "./nonces";
import { type Expiring, store } from "./pending";
import { rememberGenerated } from "./save-prompt";
import { sameSiteAsTab, senderUrl } from "./senders";
import { baseDomain, parse } from "./site";
import { hideSite, isHidden, webFrame } from "./sites";
import { getSettings, local } from "./storage";
import { type FrameTarget, toTab, toTabQuietly } from "./tabs";
import { notifyTab } from "./toast";
import * as vault from "./vault";

type Sender = chrome.runtime.MessageSender;

interface InlineMenu extends Expiring {
  tabId: number;
  /** The frame (and document) whose field opened the menu: fills go there, and only there. */
  frameId: number;
  documentId?: string;
  /** That frame's address when it opened the menu (its origin checked out). */
  url: string;
  /** The menu frame that used the nonce first. */
  menuFrame?: FrameTarget;
  /** What the field is for (older records: a login field). */
  kind?: InlineKind;
  /** What was typed in the form's user name field (for "New login"), at most MAX_USERNAME characters. */
  username?: string;
  /** A new-password field's length limits (for "Use a strong password"). */
  minLength?: number;
  maxLength?: number;
  /** The item ids the menu was given as rows (`inline:items`): the only ones `inline:fill` takes. */
  offered?: string[];
}
const menus = store<InlineMenu>("menu:");
/** At most this many offered ids are kept per menu (the rows of every refresh while it is open). */
const MAX_OFFERED = 500;

/** The fill note for a row the menu couldn't fill: the same words whatever went wrong (the reason is in PassAuth). */
const FILL_FAILED = pageText`PassAuth couldn't fill this page. Open PassAuth for details.`;

/**
 * page:inlineInfo: whether to show PassAuth's icon in this frame's fields, and whether PassAuth is locked. Off when
 * the menu is turned off, nobody is signed in, the frame isn't on the tab's site or the site is hidden.
 */
export async function inlineInfo(sender: Sender): Promise<InlineInfo> {
  const { settings, tokens, hiddenSites } = await local.get();
  const off: InlineInfo = { mode: "off", status: "locked", count: 0 };
  const top = parse(sender.tab?.url ?? "");
  if (settings.inlineMenu === "off" || !tokens || !top) return off;
  // Only frames on the same site as the tab: fill() refuses the others anyway.
  if (!sameSiteAsTab(webFrame(sender)) || isHidden(hiddenSites, top.hostname)) return off;
  // From the match index when there is one: no decrypting the vault for an icon.
  const count = await countMatching(top.href);
  return count === null ? { mode: settings.inlineMenu, status: "locked", count: 0 } : { mode: settings.inlineMenu, status: "unlocked", count };
}

/** page:inlineOpen: a nonce for a new menu in the sender's frame (one menu per tab), or null when this frame may not have one. */
export async function openInline(sender: Sender, req: InlineOpen): Promise<string | null> {
  const frame = webFrame(sender);
  const tabId = sender.tab?.id;
  const url = senderUrl(frame);
  if (tabId === undefined || sender.frameId === undefined || !url || !sameSiteAsTab(frame)) return null;
  const { hiddenSites } = await local.get();
  if (isHidden(hiddenSites, parse(sender.tab?.url ?? "")?.hostname ?? "")) return null;
  // One menu per tab.
  for (const [nonce, m] of await menus.all()) if (m.tabId === tabId) await menus.remove(nonce);
  const nonce = crypto.randomUUID();
  await menus.put(nonce, {
    tabId,
    frameId: sender.frameId,
    ...(sender.documentId ? { documentId: sender.documentId } : {}),
    url: url.href,
    kind: req.kind ?? "login",
    ...(req.username ? { username: req.username } : {}),
    ...(req.minLength ? { minLength: req.minLength } : {}),
    ...(req.maxLength ? { maxLength: req.maxLength } : {}),
    expires: Date.now() + 10 * 60_000,
  });
  return nonce;
}

/** A tab closed: its menu goes. */
export async function forgetTab(tabId: number) {
  for (const [nonce, m] of await menus.all()) if (m.tabId === tabId) await menus.remove(nonce);
}

let changing: Promise<unknown> = Promise.resolve();
/** Menu records change one at a time: the rows of a refresh are never written back into a record a fill used up. */
function serial<T>(fn: () => Promise<T>): Promise<T> {
  const p = changing.then(fn, fn);
  changing = p.catch(() => {});
  return p;
}

/** The menu `nonce` belongs to (as stored), if `sender` is the menu frame that owns it; `consume` ends it (single use). */
function menuFor(nonce: string, sender: Sender, consume = false): Promise<InlineMenu> {
  return serial(async () => {
    const m = await menus.get(nonce);
    if (!m || m.tabId !== sender.tab?.id || !sender.frameId) throw new AppError(EXPIRED, "This menu has expired. Click the field again.");
    if (!ownsNonce(nonce, sender, m.menuFrame)) throw notAllowed();
    if (consume) {
      await menus.remove(nonce);
      forgetNonce(nonce);
    } else if (!m.menuFrame) {
      m.menuFrame = thisFrame(sender);
      await menus.put(nonce, m);
    }
    return m;
  });
}

/** The field's frame (and document), as commands to the content script that opened the menu address it. */
const fieldTarget = (m: InlineMenu): FrameTarget => ({ frameId: m.frameId, documentId: m.documentId });

const closeMenu = (m: InlineMenu, refocus?: { nonce: string }) => toTabQuietly(m.tabId, { type: "inline:close", ...(refocus ? { refocus: true, nonce: refocus.nonce } : {}) }, fieldTarget(m));

/** The field's frame, as fills address it. */
const fieldFrame = (m: InlineMenu) => ({ frameId: m.frameId, ...(m.documentId ? { documentId: m.documentId } : {}), url: m.url });

const two = (s: string) => {
  const n = Number(s);
  return Number.isInteger(n) && n > 0 ? String(n % 100).padStart(2, "0") : "";
};

/** "Visa •••• 4242 · 09/28" (what the menu shows for a card). */
export function cardLabel(card: Card): string {
  const digits = card.number.replace(/\D/g, "");
  const brand = card.brand.trim() || cardBrand(digits) || "Card";
  const month = two(card.exp_month);
  const year = two(card.exp_year);
  return [digits ? `${brand} •••• ${digits.slice(-4)}` : brand, month && year ? `${month}/${year}` : ""].filter(Boolean).join(" · ");
}

/** "Alex Morgan · Home" (the person's name and the item's name), else the item's name. */
export function identityLabel(identity: Identity, itemName: string): string {
  const person = [identity.first_name, identity.last_name]
    .map((s) => s.trim())
    .filter(Boolean)
    .join(" ");
  return person && person !== itemName ? `${person} · ${itemName}` : itemName || person;
}

/** inline:items: what the menu lists for its field (see the file comment). */
export async function items(sender: Sender, nonce: string): Promise<InlineItems> {
  const list = await rows(sender, nonce);
  // The rows offered: inline:fill takes only these. Kept with the menu (the ones of earlier refreshes too).
  const ids = list.items.map((i) => i.id);
  if (ids.length) {
    await serial(async () => {
      const m = await menus.get(nonce);
      if (m) await menus.put(nonce, { ...m, offered: [...new Set([...(m.offered ?? []), ...ids])].slice(-MAX_OFFERED) });
    });
  }
  return list;
}

async function rows(sender: Sender, nonce: string): Promise<InlineItems> {
  const m = await menuFor(nonce, sender);
  const { server, settings, activeId } = await local.get();
  const kind = m.kind ?? "login";
  const host = parse(sender.tab?.url ?? "")?.hostname ?? "";
  const base = {
    server,
    theme: settings.theme,
    showIcons: await iconsShown(server, settings.showIcons),
    kind,
    site: host.replace(/^www\./, ""),
    // "Hide on example.com": what "⋯ → Hide" hides is the whole site (its base domain), so it says which.
    ...(host ? { hides: baseDomain(host) } : {}),
    strongPassword: kind === "new-password" && settings.inlineOnSignup,
  };
  if (!(await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault for the inline menu")))) return { ...base, locked: true, items: [] };
  const used = await lastUsedMap(activeId);
  if (kind === "card" || kind === "identity") {
    const entries = byLastUsed(
      vault.allEntries().filter((e) => (kind === "card" ? e.item.card : e.item.identity)),
      used,
    );
    const rows = entries.map((e): ItemSummary => {
      const s = vault.summarize(e);
      if (e.item.card) return { ...s, subtitle: cardLabel(e.item.card) };
      const identity = e.item.identity!;
      return { ...s, name: identityLabel(identity, s.name), subtitle: identity.email || [identity.address1, identity.city].filter(Boolean).join(", ") };
    });
    return { ...base, locked: false, items: rows };
  }
  let logins = byLastUsed(await matching(sender.tab?.url ?? ""), used);
  if (kind !== "otp") return { ...base, locked: false, items: logins.map(vault.summarize) };
  logins = logins.filter((e) => e.item.login?.totp);
  const codes = logins.flatMap((e) => {
    try {
      const t = vault.totp(e.item.login!.totp!);
      return [{ id: e.id, code: t.code, period: t.period, expires: t.expires }];
    } catch {
      return []; // a key the core can't read: no row for it
    }
  });
  return { ...base, locked: false, items: logins.filter((e) => codes.some((c) => c.id === e.id)).map(vault.summarize), codes };
}

/** inline:fill: fill the chosen item into the frame that opened the menu (the nonce is used up); a failure shows a note in the page. */
export async function fillFromMenu(sender: Sender, nonce: string, id: string) {
  const m = await menuFor(nonce, sender, true);
  // Only a row this menu showed: anything else is refused (and the menu is used up all the same).
  if (!m.offered?.includes(id)) {
    await closeMenu(m);
    throw notAllowed();
  }
  // Only a fill is user activity; opening or closing the menu must not keep the vault unlocked.
  await touch();
  await closeMenu(m);
  try {
    await fill(id, m.tabId, { ...fieldFrame(m), ...(m.kind === "otp" ? { otp: true } : {}) });
  } catch (e) {
    // The menu has closed: say so in the page (always the same words, so the page learns nothing), the reason stays in PassAuth.
    await noteFillProblem(m.tabId, e).catch(logged("Keeping the fill problem"));
    await notifyTab(m.tabId, FILL_FAILED);
    throw e;
  }
}

/** inline:close (the nonce is used up); `refocus`: Esc in the list, the focus goes back to the field too. */
export async function close(sender: Sender, nonce: string, refocus = false) {
  await closeMenu(await menuFor(nonce, sender, true), refocus ? { nonce } : undefined);
}

/** inline:return: Tab in the list. The content script that opened the menu puts the focus back into its field. */
export async function returnFocus(sender: Sender, nonce: string) {
  const m = await menuFor(nonce, sender);
  await toTabQuietly(m.tabId, { type: "inline:return", nonce }, fieldTarget(m));
}

/** inline:touch: a finger or pen touched the menu; the content script then checks it in every animation frame. */
export async function touched(sender: Sender, nonce: string) {
  const m = await menuFor(nonce, sender);
  await toTabQuietly(m.tabId, { type: "inline:touch", nonce }, fieldTarget(m));
}

/** inline:unlock: "Unlock PassAuth" or "Open PassAuth" in the menu, only from the menu frame that owns a live nonce (used up). */
export async function unlockFromMenu(sender: Sender, nonce: string) {
  await closeMenu(await menuFor(nonce, sender, true));
  await openPopup();
}

/** inline:new: "New login" (with the page's address and the typed user name), "New card" or "New identity" opens PassAuth's editor. */
export async function newItem(sender: Sender, nonce: string) {
  const m = await menuFor(nonce, sender, true);
  await closeMenu(m);
  const kind = m.kind === "card" || m.kind === "identity" ? m.kind : "login";
  const origin = parse(m.url)?.origin;
  const route: PopupRouteRequest =
    kind === "login" ? { page: "new", kind, ...(origin && origin !== "null" ? { url: origin } : {}), ...(m.username ? { username: m.username } : {}) } : { page: "new", kind };
  await chrome.storage.session.set({ [POPUP_ROUTE_KEY]: route });
  await openPopup();
}

/** inline:hide: "Hide on this site" — no icon or menu on the tab's site any more; every frame of the tab drops its own. */
export async function hide(sender: Sender, nonce: string) {
  const m = await menuFor(nonce, sender, true);
  await closeMenu(m);
  await hideSite(parse(sender.tab?.url ?? "")?.hostname ?? "");
  await toTabQuietly(m.tabId, { type: "inline:off" });
}

/** A password field's length limits, as the page side read them (`minlength` / `maxlength`). */
export interface LengthLimits {
  minLength?: number;
  maxLength?: number;
}

/** A password from the user's generator options, within a password field's length limits. */
export async function generateWithin(limits: LengthLimits): Promise<string> {
  const req = generatorRequest(await readGeneratorSettings());
  const max = limits.maxLength && limits.maxLength >= PASSWORD_LENGTH.min ? limits.maxLength : undefined;
  const min = limits.minLength && limits.minLength <= PASSWORD_LENGTH.max ? limits.minLength : undefined;
  if (req.mode === "password") {
    const length = Math.min(Math.max(req.options.length, min ?? 0), max ?? PASSWORD_LENGTH.max);
    return vault.generate("password", { ...req.options, length });
  }
  const phrase = await vault.generate("passphrase", { ...req.options });
  // A passphrase that doesn't fit the field: a password of the field's length instead.
  if ((max && phrase.length > max) || (min && phrase.length < min)) {
    const length = Math.min(Math.max(20, min ?? 0), max ?? PASSWORD_LENGTH.max);
    return vault.generate("password", { length, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false });
  }
  return phrase;
}

/**
 * A strong password into a password field of `frame` and the field's confirmation, kept as a pending save for the
 * page (save-prompt.ts `rememberGenerated`, marked generated), so the save prompt follows the sign-up even when
 * PassAuth doesn't see the submit. `field`: "menu", the new-password field the inline menu was opened on (its limits
 * came with the menu); "context", the password field that was right-clicked (the right-click menu's "Fill a strong
 * password"), whose limits the page side reports. `frame.url`: the frame's address as the caller checked it (on the
 * tab's site); the frame fills only while it is still at that origin.
 */
export async function fillStrongPassword(tabId: number, frame: FrameTarget & { url: string }, field: "menu" | "context", limits: LengthLimits = {}) {
  const origin = parse(frame.url)?.origin;
  if (!origin || !/^https?:/.test(origin)) throw new AppError(CANT_FILL, "PassAuth can only fill on websites.", true);
  let lengths = limits;
  if (field === "context") {
    const info = await toTab(tabId, { type: "context:field" }, frame).catch(() => null);
    if (!info?.password) throw new AppError(CANT_FILL, "Right-click a password field to fill a strong password there.", true);
    lengths = { ...(info.minLength ? { minLength: info.minLength } : {}), ...(info.maxLength ? { maxLength: info.maxLength } : {}) };
  }
  const password = await generateWithin(lengths);
  const r = await toTab(tabId, { type: "fill:generated", password, origin, ...(field === "context" ? { field } : {}) }, frame).catch(() => null);
  if (!r?.filled) throw new AppError(CANT_FILL, "PassAuth couldn't fill the new password.", true);
  await rememberGenerated(tabId, frame.url, typeof r.username === "string" ? r.username : "", password);
}

/**
 * inline:generate: "Use a strong password" on a new-password field (only there, only with `inlineOnSignup` on). The
 * password goes into the field and its confirmation, and is kept as a pending save for the page (`fillStrongPassword`).
 */
export async function generate(sender: Sender, nonce: string) {
  const m = await menuFor(nonce, sender, true);
  if (m.kind !== "new-password" || !(await getSettings()).inlineOnSignup) throw notAllowed();
  if (!(await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault for a generated password")))) throw lockedError();
  await touch();
  await closeMenu(m);
  try {
    await fillStrongPassword(m.tabId, { frameId: m.frameId, documentId: m.documentId, url: m.url }, "menu", {
      ...(m.minLength ? { minLength: m.minLength } : {}),
      ...(m.maxLength ? { maxLength: m.maxLength } : {}),
    });
  } catch (e) {
    await noteFillProblem(m.tabId, e).catch(logged("Keeping the fill problem"));
    await notifyTab(m.tabId, FILL_FAILED).catch(logged("Showing a note in the page"));
    throw e;
  }
}
