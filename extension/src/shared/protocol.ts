/**
 * PassAuth's message protocol: one map per channel, `{ [type]: Rpc<req, res> }`. A request travels as
 * `{ type, ...req }` and is answered `Reply<res>`. Pages and content scripts send through `channel<C>()`
 * (`call(type, req)`), and the background's handler tables are checked against the same maps
 * (background/handlers, `satisfies`), so a request and its handler can't disagree about a type.
 *
 * The background checks who sent each request (background/router.ts): what a channel may ask depends on the
 * sender, never on what the message says about itself.
 */
import type { NewRequestBody, PollOutcome } from "@web/lib/device-login";
import type { Identity, Item, LoginFinishResponse } from "@web/lib/types";
import { AppError, NO_ANSWER } from "./errors";
import type { PageSafeText } from "./page-text";
import type { CreateRequest, GetRequest, PasskeyRuntimeReply } from "./passkey-types";
import type {
  AfterUnlock,
  DeviceSignIn,
  DeviceSignInStart,
  EditorInfo,
  FileAccess,
  InlineInfo,
  InlineItems,
  InlineKind,
  ItemData,
  ItemList,
  LoginResult,
  PasskeyRequestInfo,
  PinUnlockResult,
  PolicyNotices,
  PopupState,
  SaveAnswer,
  SaveOffer,
  SavePrompt,
  SecurityKeys,
  Settings,
  SignInAnswer,
  SignInApproval,
  SignInRequestList,
  TotpCode,
} from "./types";

/** No fields besides `type`. */
export type None = Record<never, never>;

/** One request type: what is sent besides `type` (`None`: nothing) and what comes back. */
export interface Rpc<Req extends object, Res> {
  req: Req;
  res: Res;
}

export type ReqOf<C, K extends keyof C> = C[K] extends Rpc<infer Q, unknown> ? Q : never;
export type ResOf<C, K extends keyof C> = C[K] extends Rpc<object, infer R> ? R : never;
/** The request's fields besides `type`. */
export type Fields<C, K extends keyof C> = ReqOf<C, K>;
/** A request as it travels: `{ type, ...req }`. */
export type Message<C, K extends keyof C = keyof C> = K extends keyof C ? { type: K } & Fields<C, K> : never;
/** The answer to a request. A failure carries a code (shared/errors.ts) and a message worded for people. */
export type Reply<T> = { ok: true; data: T } | { ok: false; code: string; message: string };

// ------------------------------------------------------------ popup.html (the popup, the pop-out window)

export interface PopupApi {
  state: Rpc<None, PopupState>;
  setServer: Rpc<{ url: string }, void>;
  login: Rpc<{ email: string; password: string; secretKey?: string }, LoginResult>;
  verify2fa: Rpc<{ token: string; provider: string; code: string; remember: boolean }, void>;
  email2fa: Rpc<{ token: string }, void>;
  unlock: Rpc<{ password: string; secretKey?: string }, void>;
  /** Every account, like the vault timeout. */
  lock: Rpc<None, void>;
  logout: Rpc<None, void>;
  sync: Rpc<None, void>;
  /** `url`: the page for "Suggested"; `tabId`: its tab, for why a fill there didn't work (`fillProblem`). */
  items: Rpc<{ url?: string; tabId?: number }, ItemList>;
  item: Rpc<{ id: string }, ItemData>;
  /** The popup counts down to `expires` itself and asks again only then. */
  totp: Rpc<{ id: string }, TotpCode>;
  fill: Rpc<{ id: string; tabId: number }, void>;
  generate: Rpc<{ mode: "password" | "passphrase"; options?: Record<string, unknown> }, string>;
  /** `id`: the new item's id (a UUID the editor keeps), so trying again after a failure can't save it twice. */
  createItem: Rpc<{ item: Item; vaultId?: string; id?: string }, string>;
  updateItem: Rpc<{ id: string; item: Item }, void>;
  trashItem: Rpc<{ id: string }, void>;
  editorInfo: Rpc<None, EditorInfo>;
  settings: Rpc<{ patch: Partial<Settings> }, Settings>;
  "neverSave:remove": Rpc<{ domain: string }, void>;
  copy: Rpc<{ text: string }, void>;
  copyField: Rpc<{ id: string; field: "username" | "password" | "totp" }, void>;
  openPopup: Rpc<None, void>;
  "account:add": Rpc<None, void>;
  "account:switch": Rpc<{ id: string }, void>;
  "account:cancelAdd": Rpc<None, void>;
  /** Forget this browser for the active account: its remember-device token and its stored Secret Key. */
  "account:forgetBrowser": Rpc<None, void>;
  /** Two-step login security keys of the active account (`GET /account`). */
  securityKeys: Rpc<None, SecurityKeys>;
  /** Remove one, after the master password (fresh reauth token). */
  "securityKeys:remove": Rpc<{ id: string; password: string }, SecurityKeys>;
  /** Show PassAuth's inline menu and fill entries on this site again (Settings → Autofill). */
  "hiddenSites:remove": Rpc<{ domain: string }, void>;
  /** Right after an unlock: finish a fill that waited for it (right-click "Unlock to fill…", the fill shortcut). */
  afterUnlock: Rpc<None, AfterUnlock>;
  /** "Unlock with a PIN" for this browser session; `password`: the master password, checked first. */
  "pin:set": Rpc<{ pin: string; password: string }, void>;
  "pin:unlock": Rpc<{ pin: string }, PinUnlockResult>;
  /** Turn PIN unlock off (the PIN-wrapped keys are deleted). */
  "pin:remove": Rpc<None, void>;
  /** What the server's policies still ask of the active account (`GET /account` `policy_violations`), as notices linking to the web vault. */
  policyNotices: Rpc<None, PolicyNotices>;
  /** Sign-ins on other devices waiting for the active account's approval, each with the five words worked out here. */
  signInRequests: Rpc<None, SignInRequestList>;
  /** `approval`: with `approve`, the request as the sheet froze it and the words picked (background/sign-in-requests.ts). */
  "signInRequests:answer": Rpc<{ id: string; approve: boolean; approval?: SignInApproval }, SignInAnswer>;
  /**
   * "Sign in with another device" on the sign-in screen. The request's key lives only in the popup page that made it
   * (background/device-sign-in.ts): the worker carries its requests, pinned to `account`, and finishes the sign-in.
   */
  "deviceSignIn:start": Rpc<{ email: string }, DeviceSignInStart>;
  "deviceSignIn:create": Rpc<{ account: string; body: NewRequestBody }, unknown>;
  "deviceSignIn:poll": Rpc<{ account: string; id: string; accessCode: string }, PollOutcome>;
  "deviceSignIn:verify2fa": Rpc<{ account: string; token: string; provider: string; code: string; remember: boolean }, LoginFinishResponse>;
  /** `typedEmail`: the email typed on this device; a Secret Key that came along is kept only for it. */
  "deviceSignIn:finish": Rpc<{ account: string; signIn: DeviceSignIn; typedEmail?: string }, void>;
  "deviceSignIn:discard": Rpc<{ account: string; accessToken: string }, void>;
  /** The item's files the server no longer has (`GET /items/{id}/attachments`); null when it can't say. */
  "files:missing": Rpc<{ id: string }, string[] | null>;
  /** Downloading one of the item's files: its address and a current access token (`renew` after a 401). The popup decrypts it. */
  "files:access": Rpc<{ itemId: string; attachmentId: string; renew?: boolean }, FileAccess>;
}

// ------------------------------------------------------------ popup.html#passkey=<id> (confirmation window)

export interface PasskeyWindowApi {
  "passkey:pending": Rpc<{ requestId: string }, PasskeyRequestInfo | null>;
  /** `password`: master password, when the site requires user verification and PassAuth wasn't unlocked recently. */
  "passkey:decide": Rpc<{ requestId: string; accept: boolean; credentialId?: string; fallback?: boolean; password?: string }, void>;
}

// ------------------------------------------------------------ inline-menu.html (framed inside a web page)

export interface InlineFrameApi {
  "inline:items": Rpc<{ nonce: string }, InlineItems>;
  /** `id`: one of the rows this menu was given (`inline:items`); any other id is refused. */
  "inline:fill": Rpc<{ nonce: string; id: string }, void>;
  /** The nonce is used up. `refocus`: Esc in the list, so the focus goes back to the field too. */
  "inline:close": Rpc<{ nonce: string; refocus?: boolean }, void>;
  /** Tab in the list: the focus goes back to the field (the menu stays open). */
  "inline:return": Rpc<{ nonce: string }, void>;
  /** The user touched the menu with a finger or pen: the content script checks it in every animation frame from now on. */
  "inline:touch": Rpc<{ nonce: string }, void>;
  /** "Unlock PassAuth" (or "Open PassAuth" under "⋯") in the menu: opens PassAuth and closes the menu (the nonce is used up). */
  "inline:unlock": Rpc<{ nonce: string }, void>;
  /**
   * "Use a strong password" on a new-password field: a generated password goes into the field and its
   * confirmation, and a pending save follows it (the nonce is used up).
   */
  "inline:generate": Rpc<{ nonce: string }, void>;
  /** "New login" / "New card" / "New identity": opens PassAuth at a new item (the nonce is used up). */
  "inline:new": Rpc<{ nonce: string }, void>;
  /** "Hide on this site" under "⋯": no inline menu on this site any more (Settings can show it again; the nonce is used up). */
  "inline:hide": Rpc<{ nonce: string }, void>;
}

// ------------------------------------------------------------ save-prompt.html (framed inside a web page)

export interface SaveFrameApi {
  "save:offer": Rpc<{ nonce: string }, SaveOffer>;
  /** `target`: the login shown as selected under "Save in" (an id from the offer's `targets`, or "new"). */
  "save:answer": Rpc<{ nonce: string; accept: "save" | "never" | "dismiss"; target?: string }, SaveAnswer>;
  /** The prompt's content changed height. */
  "save:resize": Rpc<{ nonce: string; height: number }, void>;
  /** The user touched the prompt with a finger or pen: the content script checks it in every animation frame from now on. */
  "save:touch": Rpc<{ nonce: string }, void>;
}

// ------------------------------------------------------------ content scripts (every frame of every page)

/**
 * page:inlineOpen: the field the menu opens on. `username`: what is typed in its form's user name field (for "New
 * login"); `minLength` / `maxLength`: a new-password field's limits (for "Use a strong password").
 */
export interface InlineOpen {
  kind?: InlineKind;
  username?: string;
  minLength?: number;
  maxLength?: number;
}

export interface ContentApi {
  /** `keyboard`: submitted from the keyboard (the save prompt then takes the focus). */
  "page:submitted": Rpc<{ username: string; password: string; keyboard?: boolean }, boolean>;
  /** First step of an identifier-first login (user name only). */
  "page:identifier": Rpc<{ username: string }, void>;
  /** The submitted login form disappeared without a page load. */
  "page:formDone": Rpc<None, void>;
  /** This frame has a form for a fill offer (a login form, or the card or identity form the offer asked for). */
  "page:fillClaim": Rpc<{ token: string }, void>;
  "page:inlineInfo": Rpc<None, InlineInfo>;
  /** The menu's nonce, or null when this frame may not open one. */
  "page:inlineOpen": Rpc<InlineOpen, string | null>;
  /**
   * The field the user is in (focus, or the right button pressed on it) is a password field, or no longer is: the
   * right-click menu shows "Fill a strong password" only then. Sent when it changes, ahead of the menu.
   */
  "page:contextField": Rpc<{ password: boolean }, void>;
}

/**
 * The passkey bridge (content/passkey-bridge.ts, which sends `PasskeyRuntimeMessage`) → background. Answered in the
 * bridge's own shape (`PasskeyRuntimeReply`, no `Reply` envelope); `passkey:cancel` isn't answered. The `origin`
 * and `topLevel` the bridge adds are never used: the background takes both from the browser's sender information.
 */
export interface BridgeApi {
  "passkey:create": Rpc<{ options: CreateRequest; bridgeId: string }, PasskeyRuntimeReply>;
  /** `activated`: the page had transient user activation when it asked (the bridge reads it in the isolated world). */
  "passkey:get": Rpc<{ options: GetRequest; bridgeId: string; activated: boolean }, PasskeyRuntimeReply>;
  /** `gone`: the page went away (pagehide), rather than aborting its request. */
  "passkey:cancel": Rpc<{ bridgeId: string; gone: boolean }, void>;
}

// ------------------------------------------------------------ background → content script (chrome.tabs.sendMessage)

/**
 * Sent to one document only, after the background checked it (the item's websites against its address, with the
 * core's site logic: content scripts have none). `origin`: the document's web origin as checked; the document fills
 * only while it still has exactly that origin. `focused`: fill the field the inline menu was opened on.
 */
export interface FillCommand {
  username: string;
  password: string;
  totp?: string;
  origin: string;
  focused: boolean;
}

/** A card as a fill command carries it: what card fields take. `brand`: as saved, else worked out from the number. */
export interface CardFill {
  name: string;
  number: string;
  expMonth: string;
  expYear: string;
  code: string;
  brand: string;
}

/** An identity as a fill command carries it: the fields web forms ask for (never ID, passport or licence numbers). */
export type IdentityFill = Pick<
  Identity,
  "title" | "first_name" | "middle_name" | "last_name" | "company" | "email" | "phone" | "address1" | "address2" | "city" | "state" | "postal_code" | "country" | "username"
>;

/** Sent to one document only, like `FillCommand` (`origin`: as checked). Cards go only to https pages, both only to frames on the tab's site. */
export interface CardFillCommand {
  card: CardFill;
  origin: string;
  focused: boolean;
}

export interface IdentityFillCommand {
  identity: IdentityFill;
  origin: string;
  focused: boolean;
}

export interface ContentCommandApi {
  fill: Rpc<FillCommand, { filled: boolean }>;
  /**
   * No secrets and no websites: frames with a login form (`kind` absent) or a card or identity form answer with
   * page:fillClaim, and the background checks the claiming frame.
   */
  "fill:offer": Rpc<{ token: string; kind?: "card" | "identity" }, void>;
  "fill:card": Rpc<CardFillCommand, { filled: boolean }>;
  "fill:identity": Rpc<IdentityFillCommand, { filled: boolean }>;
  /**
   * "Use a strong password": into the new-password field the inline menu was opened on and its confirmation; with
   * `field: "context"` ("Fill a strong password", right-click menu) into the password field that was right-clicked.
   * Answers what is typed in the form's user name field (for the pending save). `origin`: the frame's, as checked.
   */
  "fill:generated": Rpc<{ password: string; origin: string; field?: "context" }, { filled: boolean; username: string }>;
  /** The right-click menu: whether the field it was opened on is a password field, and its length limits. No values. */
  "context:field": Rpc<None, { password: boolean; minLength?: number; maxLength?: number }>;
  /** `text` is shown inside the page, so it is page-safe text (page-text.ts): never vault data. */
  toast: Rpc<{ text: PageSafeText; theme?: Settings["theme"] }, void>;
  /** Close the open menu; with `refocus` and the menu's `nonce` (Esc in the list), the focus goes back to its field. */
  "inline:close": Rpc<{ refocus?: boolean; nonce?: string }, void>;
  /**
   * From the menu frame through the worker, which checked its nonce (the frame never posts to the page): Tab in the
   * list gives the focus back to the field; a finger or pen touched the menu.
   */
  "inline:return": Rpc<{ nonce: string }, void>;
  "inline:touch": Rpc<{ nonce: string }, void>;
  /** The site was hidden ("Hide on this site"): every frame drops its icon and menu. */
  "inline:off": Rpc<None, void>;
  /** `afterLoad`: shown because a page finished loading; not when that page asks for a password again (the sign-in most likely failed). */
  showSave: Rpc<SavePrompt & { afterLoad?: boolean }, void>;
  "save:size": Rpc<{ height: number }, void>;
  "save:close": Rpc<None, void>;
  /** From the prompt frame through the worker, which checked its nonce: a finger or pen touched the prompt. */
  "save:touch": Rpc<{ nonce: string }, void>;
}

export type ContentCommand = Message<ContentCommandApi>;

// ------------------------------------------------------------ background → offscreen document

export interface OffscreenApi {
  /** Copy `text`, and clear the clipboard after `clearAfter` seconds (0: never). */
  "offscreen:copy": Rpc<{ text: string; clearAfter: number }, true>;
}

// ------------------------------------------------------------ sending

let onFailure: (e: AppError) => void = () => {};

/** Called for every failed request before it is thrown (the popup reloads its state when PassAuth turns out to be locked). */
export function setFailureHandler(fn: (e: AppError) => void) {
  onFailure = fn;
}

/** A request without fields is sent as `call(type)`. */
type ReqArgs<C, K extends keyof C> = [keyof ReqOf<C, K>] extends [never] ? [req?: ReqOf<C, K>] : [req: ReqOf<C, K>];

/**
 * A typed sender for one channel, for extension pages and content scripts: `call(type, req)` resolves with the
 * reply's data, or rejects with an AppError carrying the background's code.
 */
export function channel<C>() {
  return async <K extends keyof C & string>(type: K, ...req: ReqArgs<C, K>): Promise<ResOf<C, K>> => {
    const r = (await chrome.runtime.sendMessage({ type, ...(req[0] as object | undefined) })) as Reply<ResOf<C, K>> | undefined;
    if (!r) throw new AppError(NO_ANSWER, "PassAuth is not responding. Reload the extension.");
    if (!r.ok) {
      const e = new AppError(r.code, r.message);
      onFailure(e);
      throw e;
    }
    return r.data;
  };
}

/** The popup page's requests (popup.html). */
export const callPopup = channel<PopupApi>();
/** The passkey confirmation window's requests (popup.html#passkey=<id>). */
export const callPasskeyWindow = channel<PasskeyWindowApi>();
/** The inline menu frame's requests (inline-menu.html). */
export const callInline = channel<InlineFrameApi>();
/** The save prompt frame's requests (save-prompt.html). */
export const callSave = channel<SaveFrameApi>();
/** Content scripts' requests. */
export const callContent = channel<ContentApi>();
