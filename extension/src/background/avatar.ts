/**
 * Profile pictures (server feature `avatar`). The picture is sealed with the Account Key by the core, so the server
 * only ever stores ciphertext. Each account's opened picture is kept in `chrome.storage.local` under its own key
 * (`avatar:<account id>`, not in the account record: that record is read on every API request, and a picture is up
 * to 256 KiB), so the popup shows it while the account is locked or in the account switcher. It goes when the
 * account signs out or is removed from this browser.
 */
import { AppError, FAILED } from "../shared/errors";
import { log } from "../shared/log";
import { AVATAR_PREFIX } from "../shared/storage-keys";
import { api } from "./api";

/** The server's limit for one picture (the core's `MAX_AVATAR_BYTES`). */
export const MAX_AVATAR_BYTES = 256 * 1024;
/** Server feature that announces profile pictures. */
export const AVATAR_FEATURE = "avatar";

/** What this browser keeps for one account: the server's picture number, and the picture (null: none, or it couldn't be opened). */
export interface CachedAvatar {
  seq: number;
  dataUrl: string | null;
}

const key = (id: string) => `${AVATAR_PREFIX}${id}`;

const isCached = (v: unknown): v is CachedAvatar => {
  const c = v as Partial<CachedAvatar> | null;
  return !!c && typeof c === "object" && typeof c.seq === "number" && (c.dataUrl === null || (typeof c.dataUrl === "string" && c.dataUrl.startsWith("data:image/")));
};

export const avatars = {
  async get(id: string): Promise<CachedAvatar | null> {
    if (!id) return null;
    const v = (await chrome.storage.local.get(key(id)))[key(id)];
    return isCached(v) ? v : null;
  },
  /** The pictures of `ids` (accounts without one are left out), in one read. */
  async many(ids: string[]): Promise<Record<string, string>> {
    if (!ids.length) return {};
    const raw = await chrome.storage.local.get(ids.map(key));
    const out: Record<string, string> = {};
    for (const id of ids) {
      const v = raw[key(id)];
      if (isCached(v) && v.dataUrl) out[id] = v.dataUrl;
    }
    return out;
  },
  set: (id: string, v: CachedAvatar) => chrome.storage.local.set({ [key(id)]: v }),
  remove: (ids: string[]) => chrome.storage.local.remove(ids.filter(Boolean).map(key)),
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
 * After a sync of account `id`: when the server's `seq` differs from the kept one, download the sealed picture, open
 * it with `open` (the unlocked account's `openAvatar`) and keep it. A picture that can't be opened is kept as "none"
 * for that number (initials), so it isn't downloaded again on every sync. `stale()`: the account was locked or
 * switched meanwhile, nothing is kept.
 */
export function refreshAvatar(id: string, seq: number | null, open: (sealed: string) => Uint8Array, stale: () => boolean): Promise<void> {
  if (seq === null || !id) return Promise.resolve();
  const running = fetching.get(id);
  if (running !== undefined) return running;
  const p = (async () => {
    const cached = await avatars.get(id);
    if ((cached?.seq ?? 0) === seq) return;
    if (seq === 0) {
      await avatars.remove([id]);
      return;
    }
    const answer = await api<unknown>("/account/avatar", { accountId: id });
    if (stale()) return;
    if (!isAnswer(answer)) throw new AppError(FAILED, "Your PassAuth server sent an unexpected answer.");
    let dataUrl: string | null = null;
    if (answer.avatar) {
      try {
        dataUrl = toDataUrl(open(answer.avatar));
      } catch (e) {
        log.warn("The profile picture couldn't be opened; initials are shown instead.", e);
      }
    }
    if (stale()) return;
    await avatars.set(id, { seq: answer.avatar_seq, dataUrl });
  })().finally(() => fetching.delete(id));
  fetching.set(id, p);
  return p;
}

/** Check a picture the popup made before it is sealed: a JPEG of at most 256 KiB. */
export function checkUpload(bytes: Uint8Array) {
  if (!bytes.length || imageType(bytes) !== "image/jpeg") throw new AppError(FAILED, "That picture couldn't be used. Choose another image.");
  if (bytes.length > MAX_AVATAR_BYTES) throw new AppError(FAILED, "That picture is too large. Choose a smaller image.");
}

/** Seal (`seal`: the unlocked account's `sealAvatar`) and upload a new picture for `id`, and keep it here. */
export async function uploadAvatar(id: string, bytes: Uint8Array, seal: (image: Uint8Array) => string) {
  checkUpload(bytes);
  const sealed = seal(bytes);
  const answer = await api<{ avatar_seq?: unknown }>("/account/avatar", { method: "PUT", body: { avatar: sealed }, accountId: id });
  const seq = typeof answer?.avatar_seq === "number" ? answer.avatar_seq : 0;
  await avatars.set(id, { seq, dataUrl: toDataUrl(bytes) });
}

/** Remove `id`'s picture on the server and here. */
export async function deleteAvatar(id: string) {
  const answer = await api<{ avatar_seq?: unknown }>("/account/avatar", { method: "DELETE", accountId: id });
  const seq = typeof answer?.avatar_seq === "number" ? answer.avatar_seq : 0;
  await avatars.set(id, { seq, dataUrl: null });
}
