/**
 * Profile pictures (server feature `avatar`). The picture is sealed with the Account Key by the core, so the server
 * only ever stores ciphertext, and so does this browser's disk: `chrome.storage.local` keeps, per account
 * (`avatar:<account id>`, not in the account record: that record is read on every API request), only the sealed
 * picture exactly as the server sent it, with its number. The opened picture lives in `chrome.storage.session`
 * (`avatarOpen:<account id>`: memory only, like the unlocked keys); it is rebuilt from the sealed copy when the
 * account is unlocked and goes when it locks, so a locked account shows its initials. Both go when the account signs
 * out or is removed from this browser.
 */
import { AppError, FAILED } from "../shared/errors";
import { log } from "../shared/log";
import { AVATAR_OPEN_PREFIX, AVATAR_PREFIX } from "../shared/storage-keys";
import { api } from "./api";

/** The server's limit for one picture (the core's `MAX_AVATAR_BYTES`). */
export const MAX_AVATAR_BYTES = 256 * 1024;
/** A sealed picture longer than this isn't kept (a picture within the limit, sealed and as text, is well under it). */
const MAX_SEALED_CHARS = 4 * MAX_AVATAR_BYTES;
/** Server feature that announces profile pictures. */
export const AVATAR_FEATURE = "avatar";

/** What this browser keeps on disk for one account: the server's picture number and the sealed picture (null: none). */
export interface KeptAvatar {
  seq: number;
  sealed: string | null;
}

/** The opened picture of an unlocked account, in memory (null: none, or it couldn't be opened). */
export interface OpenedAvatar {
  seq: number;
  dataUrl: string | null;
}

const key = (id: string) => `${AVATAR_PREFIX}${id}`;
const openKey = (id: string) => `${AVATAR_OPEN_PREFIX}${id}`;

/** A value under `avatar:<id>` as this version writes it. Anything else (0.11.0 kept the opened picture there) is never used. */
export const isKept = (v: unknown): v is KeptAvatar => {
  const c = v as Partial<KeptAvatar> | null;
  return !!c && typeof c === "object" && typeof c.seq === "number" && (c.sealed === null || typeof c.sealed === "string") && !("dataUrl" in c);
};

const isOpened = (v: unknown): v is OpenedAvatar => {
  const c = v as Partial<OpenedAvatar> | null;
  return !!c && typeof c === "object" && typeof c.seq === "number" && (c.dataUrl === null || (typeof c.dataUrl === "string" && c.dataUrl.startsWith("data:image/")));
};

export const avatars = {
  /** The sealed picture kept on disk for `id`. */
  async kept(id: string): Promise<KeptAvatar | null> {
    if (!id) return null;
    const v = (await chrome.storage.local.get(key(id)))[key(id)];
    return isKept(v) ? v : null;
  },
  keep: (id: string, v: KeptAvatar) => chrome.storage.local.set({ [key(id)]: v }),
  /** The opened picture of `id` (only while it is unlocked). */
  async get(id: string): Promise<OpenedAvatar | null> {
    if (!id) return null;
    const v = (await chrome.storage.session.get(openKey(id)))[openKey(id)];
    return isOpened(v) ? v : null;
  },
  /** The opened pictures of `ids` (accounts without one, or locked, are left out), in one read. */
  async many(ids: string[]): Promise<Record<string, string>> {
    if (!ids.length) return {};
    const raw = await chrome.storage.session.get(ids.map(openKey));
    const out: Record<string, string> = {};
    for (const id of ids) {
      const v = raw[openKey(id)];
      if (isOpened(v) && v.dataUrl) out[id] = v.dataUrl;
    }
    return out;
  },
  show: (id: string, v: OpenedAvatar) => chrome.storage.session.set({ [openKey(id)]: v }),
  /** Forget the opened pictures (a lock); the sealed copies stay. */
  hide: (ids: string[]) => chrome.storage.session.remove(ids.filter(Boolean).map(openKey)),
  /** Forget everything kept for `ids` (sign-out, account removed, picture removed). */
  async remove(ids: string[]) {
    await chrome.storage.local.remove(ids.filter(Boolean).map(key));
    await chrome.storage.session.remove(ids.filter(Boolean).map(openKey));
  },
};

/** Base64 without spreading the whole array into one call (a 256 KiB picture is more arguments than a call takes). */
export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromBase64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** The image type from the bytes' signature (JPEG, PNG, WebP), or null for anything else (never shown). */
export function imageType(b: Uint8Array): string | null {
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b.length > 12 && String.fromCharCode(...b.subarray(0, 4)) === "RIFF" && String.fromCharCode(...b.subarray(8, 12)) === "WEBP") return "image/webp";
  return null;
}

/** A picture's bytes as a data URL, or null when they aren't an image. */
export function toDataUrl(bytes: Uint8Array): string | null {
  const type = imageType(bytes);
  return type ? `data:${type};base64,${toBase64(bytes)}` : null;
}

/** The `avatar_seq` of a `/sync` user (null: the server has no profile pictures). */
export function avatarSeqOf(user: unknown): number | null {
  const seq = (user as { avatar_seq?: unknown } | null)?.avatar_seq;
  return typeof seq === "number" && Number.isSafeInteger(seq) && seq >= 0 ? seq : null;
}

interface AvatarAnswer {
  avatar: string | null;
  avatar_seq: number;
}

const isAnswer = (v: unknown): v is AvatarAnswer => {
  const a = v as Partial<AvatarAnswer> | null;
  return !!a && typeof a === "object" && (a.avatar === null || typeof a.avatar === "string") && typeof a.avatar_seq === "number";
};

// One download per account at a time.
const fetching = new Map<string, Promise<void>>();

/**
 * Open `kept` with `open` (the unlocked account's `openAvatar`) and hold the picture in memory, unless the one held is
 * of that number already. A picture that can't be opened is held as "none" for that number (initials), so it isn't
 * tried again at every sync. `stale()`: the account was locked or switched meanwhile, nothing is held.
 */
async function reveal(id: string, kept: KeptAvatar, open: (sealed: string) => Uint8Array, stale: () => boolean) {
  if ((await avatars.get(id))?.seq === kept.seq) return;
  let dataUrl: string | null = null;
  if (kept.sealed) {
    try {
      dataUrl = toDataUrl(open(kept.sealed));
    } catch (e) {
      log.warn("The profile picture couldn't be opened; initials are shown instead.", e);
    }
  }
  if (stale()) return;
  await avatars.show(id, { seq: kept.seq, dataUrl });
  // Locked while it was being written: the lock's own clearing may have run first.
  if (stale()) await avatars.hide([id]);
}

/** At unlock: the picture of `id` from the sealed copy on disk, without the network. */
export async function showKeptAvatar(id: string, open: (sealed: string) => Uint8Array, stale: () => boolean): Promise<void> {
  const kept = await avatars.kept(id);
  if (kept && !stale()) await reveal(id, kept, open, stale);
}

/**
 * After a sync of account `id`: when the server's `seq` differs from the kept one, download the sealed picture and
 * keep it as sent; then open it (`reveal`). `stale()`: the account was locked or switched meanwhile, nothing is kept.
 */
export function refreshAvatar(id: string, seq: number | null, open: (sealed: string) => Uint8Array, stale: () => boolean): Promise<void> {
  if (seq === null || !id) return Promise.resolve();
  const running = fetching.get(id);
  if (running !== undefined) return running;
  const p = (async () => {
    let kept = await avatars.kept(id);
    if ((kept?.seq ?? 0) !== seq) {
      if (seq === 0) {
        await avatars.remove([id]);
        return;
      }
      const answer = await api<unknown>("/account/avatar", { accountId: id });
      if (stale()) return;
      if (!isAnswer(answer)) throw new AppError(FAILED, "Your PassAuth server sent an unexpected answer.");
      kept = { seq: answer.avatar_seq, sealed: answer.avatar && answer.avatar.length <= MAX_SEALED_CHARS ? answer.avatar : null };
      await avatars.keep(id, kept);
    }
    if (kept && !stale()) await reveal(id, kept, open, stale);
  })().finally(() => fetching.delete(id));
  fetching.set(id, p);
  return p;
}

/** Check a picture the popup made before it is sealed: a JPEG of at most 256 KiB. */
export function checkUpload(bytes: Uint8Array) {
  if (!bytes.length || imageType(bytes) !== "image/jpeg") throw new AppError(FAILED, "That picture couldn't be used. Choose another image.");
  if (bytes.length > MAX_AVATAR_BYTES) throw new AppError(FAILED, "That picture is too large. Choose a smaller image.");
}

/**
 * Seal (`seal`: the unlocked account's `sealAvatar`) and upload a new picture for `id`; the sealed copy is kept, and
 * the picture is held in memory unless the account was locked meanwhile (`stale`).
 */
export async function uploadAvatar(id: string, bytes: Uint8Array, seal: (image: Uint8Array) => string, stale: () => boolean) {
  checkUpload(bytes);
  const sealed = seal(bytes);
  const answer = await api<{ avatar_seq?: unknown }>("/account/avatar", { method: "PUT", body: { avatar: sealed }, accountId: id });
  const seq = typeof answer?.avatar_seq === "number" ? answer.avatar_seq : 0;
  await avatars.keep(id, { seq, sealed });
  if (stale()) return;
  await avatars.show(id, { seq, dataUrl: toDataUrl(bytes) });
  if (stale()) await avatars.hide([id]);
}

/** Remove `id`'s picture on the server and here. */
export async function deleteAvatar(id: string) {
  const answer = await api<{ avatar_seq?: unknown }>("/account/avatar", { method: "DELETE", accountId: id });
  const seq = typeof answer?.avatar_seq === "number" ? answer.avatar_seq : 0;
  await avatars.keep(id, { seq, sealed: null });
  await avatars.hide([id]);
}
