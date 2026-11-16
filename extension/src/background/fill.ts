/**
 * Filling an item into a page — a login, a card or an identity — only on the user's request (popup, inline menu,
 * keyboard shortcut, right-click menu): into the frame that asked (inline menu, with its document), a frame named
 * by the caller (right-click menu), or the top frame, else a same-site iframe that claims the fill. The fill offer
 * carries only a token (and, for cards and identities, which kind of form); each claiming frame is checked
 * (`frameMayFill`, with the real origin the browser gives) before the secrets go to that frame's document. Cards are
 * filled only into https pages, cards and identities only into frames on the tab's site.
 *
 * The decision is made here, with the core's site logic (site.ts); content scripts have none. Each command carries
 * the exact origin it was checked for, and the document fills only while it is still at that origin (a frame that
 * navigated in between gets nothing; documents of one origin are one security principal, so the path needn't be
 * checked again there).
 */
import type { Card, Identity, LoginUrl } from "@web/lib/types";
import { AppError, CANT_FILL, lockedError, NOT_FOR_SITE, NOT_FOUND } from "../shared/errors";
import { logged } from "../shared/log";
import { pageText } from "../shared/page-text";
import type { CardFill, ContentCommand, IdentityFill } from "../shared/protocol";
import { copy } from "./clipboard";
import { forgetFillProblem } from "./fill-problems";
import { markUsed } from "./last-used";
import { thisFrame } from "./nonces";
import { frameMayFill, type SenderInfo, senderOrigin, senderUrl } from "./senders";
import { baseDomain, downgrade, matchesUrl, parse } from "./site";
import { webFrame } from "./sites";
import { getSettings } from "./storage";
import { type FrameTarget, TOP_FRAME, toTab } from "./tabs";
import { notifyTab } from "./toast";
import * as vault from "./vault";

/** A frame a fill goes to: the inline menu's (with its document and the address it had then) or one the caller names. `otp`: only the code. */
export type FillTarget = FrameTarget & { url: string; otp?: boolean };

/** A document a fill may go to: the frame (with its document when known) and the web origin that was checked there. */
interface Checked {
  frame: FrameTarget;
  origin: string;
}

/** A fill command for a document at `origin` (the origin the document must still have when it fills). */
type Command = (origin: string) => ContentCommand;

const describe = (u: LoginUrl) => (u.match === "regex" ? u.url : (parse(u.url)?.host ?? u.url));

/** Send a fill command to one document only (by its id when known); true if it filled something, null if nothing answered. */
const send = (tabId: number, target: FrameTarget, cmd: ContentCommand) =>
  toTab(tabId, cmd, target).then(
    (r) => !!(r as { filled?: boolean } | null | undefined)?.filled,
    () => null, // no content script in that frame (yet): the caller decides what that means
  );

// Forms inside iframes: frames are asked (without any secret or website) whether they have a login (or card, or
// identity) form; the first one to claim whose real origin passes the check gets the fill, at its document.
const claims = new Map<string, { tabId: number; frameId?: number; check: (sender: SenderInfo) => boolean; resolve: (target: Checked) => void }>();

function claimFrame(tabId: number, check: (sender: SenderInfo) => boolean, opts: { frameId?: number; kind?: "card" | "identity" } = {}): Promise<Checked | undefined> {
  return new Promise((resolve) => {
    const token = crypto.randomUUID();
    const timer = setTimeout(() => done(undefined), 700);
    function done(target: Checked | undefined) {
      clearTimeout(timer);
      claims.delete(token);
      resolve(target);
    }
    claims.set(token, { tabId, ...(opts.frameId !== undefined ? { frameId: opts.frameId } : {}), check, resolve: done });
    // Frames without a content script just don't answer; the claim times out.
    const offer: ContentCommand = { type: "fill:offer", token, ...(opts.kind ? { kind: opts.kind } : {}) };
    toTab(tabId, offer, opts.frameId !== undefined ? { frameId: opts.frameId } : undefined).catch(() => {});
  });
}

/**
 * A frame answered a fill offer (page:fillClaim). The top frame was asked directly; a claim comes from an iframe
 * (the one the offer went to, when it named one) and is checked before it gets anything.
 */
export function claimFill(token: string, sender: chrome.runtime.MessageSender) {
  const c = claims.get(token);
  if (!c || c.tabId !== sender.tab?.id || sender.frameId === undefined || sender.frameId === 0) return;
  if (c.frameId !== undefined && c.frameId !== sender.frameId) return;
  const frame = webFrame(sender);
  const origin = senderOrigin(frame);
  if (origin && c.check(frame)) c.resolve({ frame: thisFrame(sender), origin });
}

/**
 * Where a fill goes. `target` with a document: the inline menu's frame, checked with the address it had (its origin
 * was checked when the menu opened). A frame without a document (the right-click menu): the top frame directly, any
 * other frame only through a claim, which gives its real origin. No target: the top frame, then a frame that claims.
 * `top`: the tab's origin (checked by the caller), for the top frame.
 */
async function deliver(tabId: number, command: Command, fits: (sender: SenderInfo) => boolean, target: FillTarget | undefined, top: string, kind?: "card" | "identity"): Promise<boolean> {
  if (target?.documentId !== undefined) {
    const frame = webFrame({ origin: parse(target.url)?.origin, url: target.url });
    if (target.frameId !== 0 && !fits(frame)) throw new AppError(NOT_FOR_SITE, "This item isn't saved for this frame.");
    // The menu's document keeps the origin it had when the menu opened (a navigation makes a new document).
    const origin = senderOrigin(frame);
    if (!origin) throw new AppError(NOT_FOR_SITE, "This item isn't saved for this frame.");
    return (await send(tabId, target, command(origin))) ?? false;
  }
  const viaClaim = async (opts: { frameId?: number; kind?: "card" | "identity" }) => {
    const claimed = await claimFrame(tabId, fits, opts);
    return claimed !== undefined && !!(await send(tabId, claimed.frame, command(claimed.origin)));
  };
  if (target && target.frameId !== 0) return viaClaim({ frameId: target.frameId, ...(kind ? { kind } : {}) });
  const first = await send(tabId, TOP_FRAME, command(top));
  if (first === null) throw new AppError(CANT_FILL, "This page can't be filled. Reload it and try again.", true);
  if (first || target) return first;
  return viaClaim(kind ? { kind } : {});
}

/** The tab's page, if it is a website: its address, origin and site. */
async function tabPage(tabId: number): Promise<{ url: string; page: URL; origin: string; site: string }> {
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url ?? "";
  const page = parse(url);
  if (!page || !/^https?:$/.test(page.protocol)) throw new AppError(CANT_FILL, "PassAuth can only fill on websites.", true);
  return { url, page, origin: page.origin, site: baseDomain(page.hostname) };
}

async function fillLogin(entry: vault.Entry, tabId: number, target: FillTarget | undefined) {
  const login = entry.item.login!;
  const settings = await getSettings();
  const personal = vault.isPersonal(entry);
  const { url, origin, site } = await tabPage(tabId);
  if (login.urls.length && !login.urls.some((u) => matchesUrl(url, u, settings.defaultMatch, personal))) {
    // Names the login's websites: shown in PassAuth's popup, never inside the page (not page-safe).
    throw new AppError(NOT_FOR_SITE, `This login is saved for ${login.urls.map(describe).join(", ")}, not for this site.`);
  }
  if (login.urls.some((u) => downgrade(url, u))) throw new AppError(CANT_FILL, "This page isn't secure (http). PassAuth won't fill a login saved for an https site here.", true);
  const fits = (sender: SenderInfo) => frameMayFill(sender, login.urls, settings.defaultMatch, site, personal);
  const code = login.totp ? vault.totp(login.totp).code : undefined;
  const otp = target?.otp === true;
  if (otp && !code) throw new AppError(NOT_FOUND, "This login has no verification code.", true);
  // Only the code for a one-time-code field. The login's websites never go to the page side: it gets the origin checked here.
  const command: Command = (at) => ({
    type: "fill",
    username: otp ? "" : login.username,
    password: otp ? "" : login.password,
    ...(code ? { totp: code } : {}),
    origin: at,
    focused: target !== undefined,
  });
  let filled: boolean;
  try {
    filled = await deliver(tabId, command, fits, target, origin);
  } catch (e) {
    // The inline menu's frame is checked with the login's websites: say which, in PassAuth's own pages.
    if (e instanceof AppError && e.code === NOT_FOR_SITE) throw new AppError(NOT_FOR_SITE, `This login is saved for ${login.urls.map(describe).join(", ") || "another site"}, not for this frame.`);
    throw e;
  }
  if (!filled) throw new AppError(CANT_FILL, otp ? "PassAuth couldn't find the field for the code." : "PassAuth couldn't find a login form on this page.", true);
  if (!otp && code && settings.autoCopyTotp) {
    await copy(code);
    await notifyTab(tabId, pageText`Verification code copied. Paste it when the site asks.`);
  }
}

/** What a card fill carries: the brand as saved, else worked out from the number. */
function cardFill(card: Card): CardFill {
  return { name: card.cardholder_name, number: card.number, expMonth: card.exp_month, expYear: card.exp_year, code: card.code, brand: card.brand.trim() || cardBrand(card.number) };
}

/** What an identity fill carries: never its ID, passport or licence numbers. */
function identityFill(i: Identity): IdentityFill {
  const { title, first_name, middle_name, last_name, company, email, phone, address1, address2, city, state, postal_code, country, username } = i;
  return { title, first_name, middle_name, last_name, company, email, phone, address1, address2, city, state, postal_code, country, username };
}

/** A card's brand from its number ("Visa", "Mastercard", …), or "". */
export function cardBrand(number: string): string {
  const n = number.replace(/\D/g, "");
  if (/^4/.test(n)) return "Visa";
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(n)) return "Mastercard";
  if (/^3[47]/.test(n)) return "American Express";
  if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
  if (/^3(0[0-5]|[68])/.test(n)) return "Diners Club";
  if (/^35(2[89]|[3-8])/.test(n)) return "JCB";
  if (/^62/.test(n)) return "UnionPay";
  return "";
}

async function fillCard(card: Card, tabId: number, target: FillTarget | undefined) {
  const { page, origin, site } = await tabPage(tabId);
  if (page.protocol !== "https:") throw new AppError(CANT_FILL, "PassAuth fills cards only on secure (https) pages.", true);
  const { defaultMatch } = await getSettings();
  // A frame on the tab's site (no websites: frameMayFill's same-site rule), with an https address.
  const fits = (sender: SenderInfo) => senderUrl(sender)?.protocol === "https:" && frameMayFill(sender, [], defaultMatch, site, false);
  const command: Command = (at) => ({ type: "fill:card", card: cardFill(card), origin: at, focused: target !== undefined });
  const filled = await deliver(tabId, command, fits, target, origin, "card");
  if (!filled) throw new AppError(CANT_FILL, "PassAuth couldn't find card fields on this page.", true);
}

async function fillIdentity(identity: Identity, tabId: number, target: FillTarget | undefined) {
  const { origin, site } = await tabPage(tabId);
  const { defaultMatch } = await getSettings();
  const fits = (sender: SenderInfo) => frameMayFill(sender, [], defaultMatch, site, false);
  const command: Command = (at) => ({ type: "fill:identity", identity: identityFill(identity), origin: at, focused: target !== undefined });
  const filled = await deliver(tabId, command, fits, target, origin, "identity");
  if (!filled) throw new AppError(CANT_FILL, "PassAuth couldn't find name or address fields on this page.", true);
}

/**
 * Fill an item into the page, by its type. `target`: the frame (and document) the inline menu was opened from with
 * the address it had then, or a frame the caller names (the right-click menu); otherwise the top frame, then a
 * same-site iframe that has a matching form. The item counts as used (last-used.ts) once it was filled.
 */
export async function fill(id: string, tabId: number, target?: FillTarget) {
  if (!(await vault.ensureUnlocked())) throw lockedError();
  const entry = vault.getEntry(id);
  if (!entry) throw new AppError(NOT_FOUND, "This item isn't in your vault any more.", true);
  const { item } = entry;
  if (item.login) await fillLogin(entry, tabId, target);
  else if (target?.otp) throw new AppError(NOT_FOUND, "This login has no verification code.", true);
  else if (item.card) await fillCard(item.card, tabId, target);
  else if (item.identity) await fillIdentity(item.identity, tabId, target);
  else throw new AppError(NOT_FOUND, "PassAuth fills logins, cards and identities only.", true);
  await markUsed(vault.owner().id, id).catch(logged("Noting when an item was used"));
  // It worked: an earlier fill problem on this page is no longer the story.
  await forgetFillProblem(tabId).catch(logged("Forgetting a fill problem"));
}

/** Fill an item (login, card or identity) into the tab: into frame `frameId` when given (the right-click menu), else as `fill` does without a target. */
export function fillItem(id: string, tabId: number, frameId?: number) {
  return fill(id, tabId, frameId === undefined ? undefined : { frameId, url: "" });
}
