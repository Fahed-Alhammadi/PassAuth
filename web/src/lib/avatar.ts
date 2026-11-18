/**
 * Profile picture (servers with the `avatar` feature). The server keeps it sealed with the Account Key (core
 * `sealAvatar`/`openAvatar`), so only the account's own devices see it. `/sync` carries `user.avatar_seq` (0: never set;
 * absent: the server has no pictures); when it differs from the one opened here, the picture is fetched and opened.
 *
 * The web vault keeps the opened picture in memory only, as an object URL, from unlock until lock or sign-out
 * (`clear`, which revokes it). Uploads are always a fresh 256×256 JPEG drawn here: the original file (and its EXIF/GPS
 * data) never leaves the device.
 */
import { useSyncExternalStore } from "react";
import { api } from "./api";

/** Largest picture the server and the core take (core `MAX_AVATAR_BYTES`). */
export const MAX_AVATAR_BYTES = 256 * 1024;
/** Side of the square picture, in pixels. */
export const AVATAR_SIZE = 256;
/** JPEG qualities tried in turn until the picture fits. */
export const AVATAR_QUALITIES = [0.85, 0.75, 0.65, 0.55, 0.45, 0.35, 0.25] as const;

export interface AvatarState {
  /** The `avatar_seq` the shown picture belongs to (-1: none known yet). */
  seq: number;
  /** Object URL of the opened JPEG; null: no picture (initials). */
  url: string | null;
}

export interface AvatarDeps {
  /** `GET /api/account/avatar`. */
  get: () => Promise<{ avatar?: unknown; avatar_seq?: unknown } | null>;
  createUrl: (jpeg: Uint8Array) => string;
  revokeUrl: (url: string) => void;
}

const EMPTY: AvatarState = { seq: -1, url: null };

/** The picture store (one per app; tests make their own with fake deps). */
export function createAvatarStore(deps: AvatarDeps) {
  let state: AvatarState = EMPTY;
  /** Bumped by `clear` and by every newer seq: an answer for an older request is dropped. */
  let generation = 0;
  /** The seq being fetched (so repeated syncs don't start the same fetch twice). */
  let fetching: number | null = null;
  const subs = new Set<() => void>();

  function publish(next: AvatarState) {
    if (state.url && state.url !== next.url) deps.revokeUrl(state.url);
    state = next;
    subs.forEach((fn) => fn());
  }

  function show(seq: number, jpeg: Uint8Array | null) {
    publish({ seq, url: jpeg && jpeg.length ? deps.createUrl(jpeg) : null });
  }

  return {
    get: () => state,
    subscribe(fn: () => void) {
      subs.add(fn);
      return () => {
        subs.delete(fn);
      };
    },
    /**
     * The seq from a `/sync` answer. Fetches and opens the picture only when it differs from the one shown (or being
     * fetched). A picture that can't be fetched or opened shows initials; the next sync with a newer seq tries again.
     */
    async note(seq: unknown, open: (sealed: string) => Uint8Array): Promise<void> {
      if (typeof seq !== "number" || !Number.isFinite(seq)) return;
      if (seq === state.seq || seq === fetching) return;
      if (seq === 0) {
        generation++;
        fetching = null;
        return show(0, null);
      }
      const gen = ++generation;
      fetching = seq;
      try {
        const r = await deps.get();
        if (gen !== generation) return;
        const sealed = typeof r?.avatar === "string" && r.avatar ? r.avatar : null;
        const at = typeof r?.avatar_seq === "number" ? r.avatar_seq : seq;
        let jpeg: Uint8Array | null = null;
        if (sealed) {
          try {
            jpeg = open(sealed);
          } catch {
            jpeg = null; // not ours, or damaged: initials
          }
        }
        show(at, jpeg);
      } catch {
        // Unreachable or refused: keep what's shown; a later sync asks again.
      } finally {
        if (gen === generation) fetching = null;
      }
    },
    /** A picture this device just uploaded (no need to fetch it back), or null after removing it. */
    set(seq: number, jpeg: Uint8Array | null) {
      generation++;
      fetching = null;
      show(seq, jpeg);
    },
    /** Lock or sign-out: forget the picture and revoke its URL. */
    clear() {
      generation++;
      fetching = null;
      if (state !== EMPTY) publish(EMPTY);
    },
  };
}

export type AvatarStore = ReturnType<typeof createAvatarStore>;

export const avatars: AvatarStore = createAvatarStore({
  get: () => api<{ avatar?: unknown; avatar_seq?: unknown } | null>("/account/avatar"),
  createUrl: (jpeg) => URL.createObjectURL(new Blob([jpeg as BlobPart], { type: "image/jpeg" })),
  revokeUrl: (url) => URL.revokeObjectURL(url),
});

/** The account's picture URL (null: show initials). */
export function useAvatarUrl(): string | null {
  const url = () => avatars.get().url;
  return useSyncExternalStore(avatars.subscribe, url, url);
}

// ------------------------------------------------------------- set / remove

/** The centred square of a `width`×`height` image (its source rectangle). */
export function squareCrop(width: number, height: number): { sx: number; sy: number; side: number } {
  const side = Math.min(width, height);
  return { sx: Math.floor((width - side) / 2), sy: Math.floor((height - side) / 2), side };
}

export const AVATAR_TOO_BIG = "This picture can't be made small enough. Choose another one.";

/** Encode at falling qualities until the result is at most `max` bytes. */
export async function encodeWithinLimit(encode: (quality: number) => Promise<Blob | null>, max = MAX_AVATAR_BYTES): Promise<Uint8Array> {
  for (const q of AVATAR_QUALITIES) {
    const blob = await encode(q);
    if (!blob) break;
    if (blob.size <= max) return new Uint8Array(await blob.arrayBuffer());
  }
  throw new Error(AVATAR_TOO_BIG);
}

export const AVATAR_UNREADABLE = "This file isn't a picture PassAuth can read. Choose a JPEG, PNG or WebP image.";

/** Load an image file in the page (never uploaded as it is). */
function loadImage(file: Blob): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file);
  const img = new Image();
  return new Promise<HTMLImageElement>((resolve, reject) => {
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error(AVATAR_UNREADABLE));
    img.src = url;
  }).finally(() => URL.revokeObjectURL(url));
}

/** The picture to upload: the image's centred square, 256×256, as a JPEG of at most 256 KiB (no metadata). */
export async function makeAvatarJpeg(file: Blob): Promise<Uint8Array> {
  const img = await loadImage(file);
  const width = img.naturalWidth;
  const height = img.naturalHeight;
  if (!width || !height) throw new Error(AVATAR_UNREADABLE);
  const { sx, sy, side } = squareCrop(width, height);
  const canvas = document.createElement("canvas");
  canvas.width = AVATAR_SIZE;
  canvas.height = AVATAR_SIZE;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error(AVATAR_UNREADABLE);
  // JPEG has no transparency: transparent pixels become white, not black.
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, AVATAR_SIZE, AVATAR_SIZE);
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(img, sx, sy, side, side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
  return encodeWithinLimit((q) => new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", q)));
}

/** Seal and upload a picture made by `makeAvatarJpeg`; shown here at once. */
export async function uploadAvatar(jpeg: Uint8Array, seal: (jpeg: Uint8Array) => string, store: AvatarStore = avatars): Promise<void> {
  const r = await api<{ avatar_seq?: unknown } | null>("/account/avatar", { method: "PUT", body: { avatar: seal(jpeg) } });
  if (typeof r?.avatar_seq === "number") store.set(r.avatar_seq, jpeg);
}

/** Remove the picture (initials again). */
export async function removeAvatar(store: AvatarStore = avatars): Promise<void> {
  const r = await api<{ avatar_seq?: unknown } | null>("/account/avatar", { method: "DELETE" });
  store.set(typeof r?.avatar_seq === "number" ? r.avatar_seq : -1, null);
}

/** Initials shown without a picture: first letters of the first and last name ("Alex Morgan" → "AM"), else of the email. */
export function initialsOf(name: string, email: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length) {
    const first = [...words[0]][0] ?? "";
    const last = words.length > 1 ? ([...words[words.length - 1]][0] ?? "") : "";
    return (first + last).toUpperCase();
  }
  return ([...email.trim()][0] ?? "?").toUpperCase();
}
