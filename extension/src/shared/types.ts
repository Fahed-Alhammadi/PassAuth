/** Data shapes that travel between PassAuth's contexts (the requests themselves are in protocol.ts). */
import type { Bundle, Item, ItemKind, UrlMatch } from "@web/lib/types";

export type Status = "setup" | "logged-out" | "locked" | "unlocked";

/** Minutes of inactivity, or a special trigger. */
export type VaultTimeout = number | "immediately" | "system-lock" | "restart" | "never";

export interface Settings {
  vaultTimeout: VaultTimeout;
  timeoutAction: "lock" | "logout";
  /** Inline autofill menu on login fields. */
  inlineMenu: "focus" | "click" | "off";
  autoCopyTotp: boolean;
  /** Seconds; 0 = never. */
  clearClipboard: number;
  showIcons: boolean;
  defaultMatch: Exclude<UrlMatch, "default">;
  askToSave: boolean;
  theme: "system" | "light" | "dark";
  /** Number of matching logins on the toolbar icon. */
  badge: boolean;
  /** PassAuth entries in the page's right-click menu. */
  contextMenu: boolean;
  /** Offer a strong password in the inline menu on sign-up and change-password fields. */
  inlineOnSignup: boolean;
  /** Popup list density: "compact" fits more rows (smaller rows, no site icons' padding). */
  density?: "comfortable" | "compact";
}

export interface AccountSummary {
  id: string;
  email: string;
  name: string;
  server: string;
  status: Status;
  /** The account's profile picture (a data URL), when it has one. */
  avatar?: string;
}

export interface PopupState {
  status: Status;
  activeId: string;
  /** Signed-in (or signed-out but remembered) accounts on this device. */
  accounts: AccountSummary[];
  /** Profile name of the active account ("" if not set). */
  name: string;
  /** The active account's profile picture (a data URL), when it has one; else its initials are shown. */
  avatar?: string;
  /** The account is unlocked and its server has profile pictures (feature `avatar`): Change picture / Remove are offered. */
  avatarEditable?: boolean;
  server: string;
  email: string;
  secretKeyRequired: boolean;
  secretKeyStored: boolean;
  /** This browser has a two-step "remember this device" token for the active account. */
  rememberedDevice: boolean;
  settings: Settings;
  lastSync: number;
  neverSave: string[];
  /** Sites (base domains) where PassAuth hides its inline menu and fill entries. */
  hiddenSites: string[];
  /** A PIN-wrapped copy of the active account's keys is in this browser session: the lock screen offers "Unlock with PIN". */
  pinUnlock?: boolean;
  /** The server requires two-step login and this account has no method yet (403 `two_step_required`): the popup says so instead of the vault. */
  twoStepRequired?: boolean;
  /** The longest vault timeout the servers' policies allow, in minutes (absent: no limit). */
  timeoutLimit?: number;
  /** The vault timeout the user had chosen before a policy lowered it (until they choose again). */
  timeoutLowered?: VaultTimeout;
  /** Website icons from the server: the "Show website icons" setting, and the server offers them (api.ts `siteIconsShown`). */
  iconsShown?: boolean;
  /** The server lets another device approve a sign-in (`login_with_device`): the sign-in screen offers it. */
  deviceSignIn?: boolean;
}

/** What the server's policies ask of the active account (`GET /account` `policy_violations`), as popup notices. */
export interface PolicyNotices {
  /** Identifies the account and the set of violations, so a dismissed notice comes back when the set changes ("" when none). */
  key: string;
  notices: { text: string; url?: string; label?: string }[];
}

/**
 * chrome.storage.session `popupRoute`: a page the popup opens once at its next start (it reads the key and removes
 * it). Written by the background (right-click menu, save prompt, inline menu) right before it opens the popup.
 */
export type PopupRouteRequest = { page: "new"; kind: "login" | "card" | "identity"; url?: string; username?: string } | { page: "generator" };

/** The popup's answer after an unlock (`afterUnlock`): a fill that waited for the unlock (right-click menu, shortcut) was done. */
export interface AfterUnlock {
  filled: boolean;
}

/** `pin:unlock`: unlocked, or a wrong PIN with the tries left (0: the PIN was removed; the master password is needed). */
export type PinUnlockResult = { unlocked: true } | { unlocked: false; triesLeft: number };

export interface ItemSummary {
  id: string;
  name: string;
  subtitle: string;
  /** Host of the first website, for the site icon. */
  host: string;
  /** Website to open from the list (first http(s) address), or "". */
  url: string;
  folder: string;
  kind: ItemKind;
  favorite: boolean;
  hasPassword: boolean;
  hasTotp: boolean;
  passkeys: number;
  vaultName: string;
  /** Vault id (the popup's vault filter). */
  vaultId?: string;
  /** In a vault someone shared with the user (not one of their own). */
  shared?: boolean;
  /** Signed sharing: "Not yet signed" (a share from before), or "Signed by <email> (account deleted)". */
  vaultLabel?: string;
  /** Logins: the user name ("" when none). */
  username?: string;
  /** Logins: every saved website address, for search. */
  websites?: string[];
  tags?: string[];
}

/**
 * A row of the list for an item that isn't shown: one from a newer version of PassAuth (`note`: "Update PassAuth to
 * see this item."), or one that can't be opened (`name`: its last known name, when this browser has one).
 */
export interface OtherItem {
  id: string;
  title: string;
  note?: string;
  /** For an owner or admin of the vault of an item from a newer version: where it can be deleted for good. */
  hint?: string;
  name?: string;
  vaultName: string;
}

/** The popup's item list: logins for the current page, and everything. */
export interface ItemList {
  suggested: ItemSummary[];
  all: ItemSummary[];
  /** Vaults shared with the account and waiting to be accepted (in the web vault), and which ones (for dismissing the notice). */
  invitations?: { count: number; key: string };
  /** Why the last fill from the page's inline menu, right-click menu or shortcut didn't work on the tab's page (no secrets). */
  fillProblem?: string;
  /** Signed sharing: shared vaults that failed a check, account-wide warnings and invitations that can't be accepted. */
  sharing?: SharingNotice;
  /** Items the server sent in an older version than this browser had seen (background/item-revs.ts); `key`: for dismissing. */
  rollback?: { text: string; key: string };
  /**
   * Vaults that show the manifest warning (background/manifests.ts `ManifestNotice`): per vault what is wrong (`text`),
   * where it is resolved when not here (`hint`; `open`: in the web vault), and whether "Use the server's copy" is
   * offered (`accept`: the served copy checks out on its own; `confirm`: its confirmation; `forget`: the server shows
   * no record, so the confirmation is `confirm.forgetBody`). They stay readable; nothing is written into them
   * meanwhile. Also the vaults that hold an item that can't be opened (their notice; nothing is held for those).
   */
  manifest?: {
    vaults: { id: string; name: string; text: string; hint?: string; accept?: boolean; forget?: boolean; open?: boolean }[];
    key: string;
    confirm: { action: string; title: string; body: string; forgetBody: string };
  };
  /** Vaults that aren't checked since "no record" was accepted for them: the quiet note (`key`: for dismissing). */
  notChecked?: { text: string; vaults: { id: string; name: string }[]; key: string };
  /** Items that aren't shown: from a newer version of PassAuth, or that can't be opened. */
  others?: OtherItem[];
  /** What this browser remembers of the account's vaults can't be read: the notice, with "Reset on this device" and its confirmation. */
  memory?: { text: string; action: string; body: string };
  /** The server is one this version refuses ("Update your PassAuth server to keep using this app."): the list is the offline copy. */
  serverProblem?: string;
}

/**
 * Signed sharing for the active account, as the popup's notice shows it (background/signed-sharing.ts). Refused vaults
 * are never named from their key (it failed); a pinned person whose keys changed is named by the email pinned with the
 * old keys. Every name and email is cleaned (one line, no invisible characters, at most 128 characters).
 */
export interface SharingNotice {
  refused: {
    vaultId: string;
    reason: string;
    /** "changed": a pinned person's keys changed ("Trust the new key" after comparing); "email_conflict": a known email under a new account (nothing to trust here). */
    changed?: { kind: "changed" | "email_conflict"; userId: string; email: string; fingerprint: string; newEmail: string };
  }[];
  /**
   * Shared vaults the server added to this account that it never accepted, or whose key was replaced on a vault never
   * seen signed: not used until the user accepts them (here or in the web vault). Only signed ones the core marks
   * `declinable` can be declined (in the web vault); unsigned ones are accepted by the key id shown where that is allowed, else they stay
   * locked ("Ask the vault's owner to sign this vault").
   */
  waiting: {
    vaultId: string;
    name: string;
    text: string;
    signer?: VaultSigner;
    acceptable: boolean;
    /** What "sharing:accept" must send: the consent token of exactly what was shown (signer, email, key id, roster, role). */
    token: string;
    /** A new key on a vault already accepted but never seen signed: "Not now" keeps it locked (no Decline). */
    replaced: boolean;
    /** The account held this vault with its own key wrap (the text carries the extra warning). */
    own?: boolean;
    /** Signed for the first time on a vault the account holds: Accept only after comparing the signer's fingerprint. */
    firstSigned?: boolean;
    /** Decline may be offered (in the web vault): only a signed, plain consent the core marks declinable. */
    declinable?: boolean;
    /** The key id of an unsigned vault that may be accepted: shown, and what accepting names. */
    keyId?: string;
    note?: string;
  }[];
  /** Account-wide warnings (sharing paused on this device, an older list of known keys from the server). */
  warnings: string[];
  /** Waiting invitations that can't be accepted as they are, with why. */
  invitations: { vaultId: string; text: string }[];
  /** The web vault's Vaults & sharing page (accept or decline there). */
  vaultsUrl?: string;
  /** Identifies the set, so a dismissed notice comes back when it changes. */
  key: string;
}

/**
 * Who signed the share of a vault (signed sharing), for the item view and the notice: the email pinned for them first
 * (`pinned`), else the one the server lists (first time seen); `listedAs` = what the server lists now when it differs,
 * or its name for them. "Verified" (`verified`) only ever goes with a pinned email.
 */
export interface VaultSigner {
  email: string;
  pinned: boolean;
  listedAs?: string;
  /** The signer's account was deleted after signing. */
  deleted: boolean;
  /** Identity fingerprint, computed here from the signer's keys. */
  fingerprint: string;
  /** The user compared it with them ("Verified"). */
  verified: boolean;
}

/** This account's own signing identity (Settings → Account security). */
export interface SharingIdentity {
  /** Computed here from the unlocked key, never the server's; null without one (older server, or not made yet). */
  fingerprint: string | null;
  /** The server lists a signing key that isn't this account's: sharing is paused here. */
  paused: boolean;
}

/** A sign-in on another device waiting for this account's answer (background/sign-in-requests.ts), as the popup shows it. */
export interface SignInRequestView {
  id: string;
  /** The request's key and the server's challenge: the popup freezes them (with everything else) when its sheet opens. */
  publicKey: string;
  challenge: string;
  /** The five words, worked out from the request's own public key (never the server's); null when it can't be read: then only Deny. */
  phrase: string | null;
  /** The words to pick from ("Which words does the new device show?"), in the order shown; empty when the key can't be read. */
  choices: string[];
  /** As the new device named itself ("Chrome on macOS"), its kind ("web", "mobile"…) and app (`X-PassAuth-Client`): claims, shown as such. */
  deviceName: string;
  deviceKind: string;
  client: string | null;
  /** Its address, when the server keeps addresses. */
  ip: string | null;
  /** Unix seconds, the server's clock. */
  createdAt: number;
  expiresAt: number;
}

/**
 * A sign-in another device approved, finished by the popup (background/device-sign-in.ts): the session the approval
 * brought and the account the popup opened from its sealed key (`keys`: `Account.toSessionBytes()`, base64).
 */
export interface DeviceSignIn {
  email: string;
  accessToken: string;
  refreshToken: string;
  bundle: Bundle;
  /** The account the sealed key opened (the sign-in's `user_id`; the bundle's `account_id`). */
  accountId: string;
  keys: string;
  /** The Secret Key the approving app sent with it, if any. */
  secretKey?: string;
  /** "Remember this browser" after two-step login. */
  rememberToken?: string;
}

/** What starting "Sign in with another device" needs from the worker: the account it is for, and how this browser names itself. */
export interface DeviceSignInStart {
  account: string;
  device: { id: string; name: string; kind: string };
  rememberToken: string | null;
}

/** The waiting requests, and the ids answered lately (here or on another device): a sheet whose request went says why. */
export interface SignInRequestList {
  requests: SignInRequestView[];
  answered: string[];
}

/** An approval: the request as its sheet froze it, and the words the user picked. */
export interface SignInApproval {
  publicKey: string;
  challenge: string;
  phrase: string;
}

/**
 * How answering a sign-in request ended: given, or not needed any more (expired, answered elsewhere first, gone), or
 * denied because the words picked weren't the request's ("mismatch").
 */
export interface SignInAnswer {
  outcome: "done" | "expired" | "answered" | "gone" | "mismatch";
  /** An approval that went through: the 6-digit code the user enters on the new device (shown until Done). */
  code?: string;
}

/** What the popup needs to download one of an item's files itself (background/attachments.ts). */
export interface FileAccess {
  /** `<server>/api/attachments/<id>`. */
  url: string;
  /** A current access token for the account (the popup asks for a new one after a 401). */
  token: string;
  /** The `X-PassAuth-Client` value every request carries. */
  client: string;
}

/** One item for the item page and the editor. */
export interface ItemData {
  item: Item;
  vaultName: string;
  vaultId: string;
  canWrite: boolean;
  weakPassword: boolean;
  /** Signed sharing: "Not yet signed", or who signed the vault's share (see `signer`). */
  vaultLabel?: string;
  signer?: VaultSigner;
  /** By the index of a website in `item.login.urls`: why its regular expression is refused (it never matches). */
  regexErrors?: Record<number, string>;
  /** The server sent an older version of this item than this browser had seen: the warning to show. */
  olderVersion?: string;
  /** The item's vault doesn't match its manifest (background/manifests.ts): the warning and what to do. Nothing in it can be changed meanwhile. */
  vaultWarning?: string;
}

/** A verification code as the background made it; `expires`: when it changes (ms, see totp.ts). */
export interface TotpCode {
  code: string;
  remaining: number;
  period: number;
  expires: number;
}

/** Vaults the user can add items to (their own first), the one preselected, and folder names in use. */
export interface EditorInfo {
  vaults: { id: string; name: string }[];
  defaultVault: string;
  folders: string[];
}

export type TwoFactorChallenge = { token: string; providers: string[] };

/** Sign-in: done, or a two-step code is needed first. */
export type LoginResult = { done: true } | { twoFactor: TwoFactorChallenge };

/** A security key / passkey registered for two-step login (not a passkey saved in a login). */
export interface SecurityKey {
  id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export interface SecurityKeys {
  keys: SecurityKey[];
  /** Enabled two-step methods besides recovery codes (`totp`, `email`, `passkey`). */
  methods: string[];
}

/** A login the save prompt offers under "Save in". Never carries a password (the core's save rule, background/site.ts). */
export interface SaveTarget {
  id: string;
  name: string;
  username: string;
  /** Set when the login lives in a shared vault: that vault's name. */
  vault?: string;
}

/**
 * All the page side ever learns about a save prompt: the nonce that binds the
 * prompt frame to the pending save, and how tall to make the frame.
 */
export interface SavePrompt {
  nonce: string;
  height: number;
  /** The form was submitted from the keyboard: the prompt takes the focus (otherwise it is announced politely). */
  focus?: boolean;
}

/** A login for another site that the save prompt offers to add this site to. */
export interface AddSiteTarget {
  id: string;
  name: string;
  username: string;
  /** The login's own site ("gmail.com"). */
  site: string;
}

/** What the save prompt shows. Only the prompt frame (an extension page) gets it, never the content script. */
export interface SaveOffer {
  host: string;
  /** The user name that was typed ("" when the page had no user-name field). */
  username: string;
  /**
   * The choices under "Save in", besides "New login": the user's own logins for this site, then any login in a
   * shared vault saved under the typed user name, which names its vault and is never preselected (the save rule).
   */
  targets: SaveTarget[];
  /**
   * Only when nothing is saved for this site: the user's own logins for other sites with exactly the typed user name
   * and password (the same account used here). Picking one adds this site to it. Never preselected.
   */
  addTo?: AddSiteTarget[];
  /** Preselected: one of the user's own `targets` (update it) or "new" (save a new login). */
  selected: string;
  theme: Settings["theme"];
  /** The password is one PassAuth generated ("Use a strong password"): the prompt doesn't go away by itself. */
  generated?: boolean;
}

/** The background's reply to the prompt's answer. */
export type SaveAnswer =
  /** Applied or dismissed: the prompt closes. */
  | { done: true }
  /** Nothing was saved. `retry`: the user can try again from the same prompt. */
  | { error: string; retry: boolean }
  /** The login that was shown as the target is gone or read-only now: show these choices and ask again. */
  | { again: SaveOffer; notice: string };

export interface InlineInfo {
  mode: Settings["inlineMenu"];
  status: "locked" | "unlocked";
  count: number;
}

/** What the field an inline menu belongs to is for (content/fields.ts `FieldKind`): the menu's rows follow it. */
export type InlineKind = "login" | "new-password" | "otp" | "card" | "identity";

export interface InlineItems {
  server: string;
  theme: Settings["theme"];
  /** Website icons from the server: the setting, and the server offers them (api.ts `siteIconsShown`). */
  showIcons: boolean;
  locked: boolean;
  /** Logins for the page (last used first); on one-time-code fields those with a code; cards; identities. */
  items: ItemSummary[];
  kind?: InlineKind;
  /** The page's host, for the list's label ("2 logins for example.com"). */
  site?: string;
  /** The site "⋯ → Hide on …" hides: the page's base domain, the whole site ("Hide on example.com"). */
  hides?: string;
  /** The current code of each row on a one-time-code field (`expires`: when it changes, ms). */
  codes?: { id: string; code: string; period: number; expires: number }[];
  /** "Use a strong password" in the footer: a new-password field, with `inlineOnSignup` on. */
  strongPassword?: boolean;
}

/** A passkey request as the confirmation window shows it (background/passkey-handler.ts). */
export interface PasskeyRequestInfo {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  /**
   * Sign-in: matching passkeys. Creation: logins to save in (`preferred` = the user's own login for this exact
   * site, preselected; `vault` = the shared vault a login lives in, shown on its row).
   */
  candidates: { credentialId: string; userName: string; itemName: string; preferred?: boolean; vault?: string }[];
  /** Creation: the choice preselected under "Save in" (a candidate's id, or "new"), as the core picks it. */
  selected?: string;
  /** The site requires user verification: confirm with the master password. */
  needsPassword: boolean;
  /** For the site icon. */
  server: string;
  /** Website icons from the server: the setting, and the server offers them (api.ts `siteIconsShown`). */
  showIcons: boolean;
}
