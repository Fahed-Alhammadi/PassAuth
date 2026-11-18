/**
 * A profile picture from a file the user picked: centre-cropped to a square, drawn at 256×256 and re-encoded as JPEG
 * (which drops EXIF and location data: the original file is never uploaded), at quality 0.85, lowered until it fits
 * in 256 KiB.
 */

export const AVATAR_SIZE = 256;
export const MAX_AVATAR_BYTES = 256 * 1024;
const QUALITIES = [0.85, 0.75, 0.65, 0.55, 0.45, 0.35];

/** The largest centred square of a `width`×`height` image: the source rectangle to draw. */
export function squareCrop(width: number, height: number): { sx: number; sy: number; size: number } {
  const size = Math.min(width, height);
  return { sx: Math.floor((width - size) / 2), sy: Math.floor((height - size) / 2), size };
}

/** Encode at falling qualities until the result fits in `max` bytes; throws when even the lowest doesn't. */
export async function encodeWithin(encode: (quality: number) => Promise<Blob>, max = MAX_AVATAR_BYTES): Promise<Uint8Array> {
  for (const q of QUALITIES) {
    const blob = await encode(q);
    if (blob.size <= max) return new Uint8Array(await blob.arrayBuffer());
  }
  throw new Error("That picture is too large. Choose a smaller image.");
}

/** The 256×256 JPEG for `file`; a file that isn't an image the browser can read is refused with a message. */
export async function avatarJpeg(file: Blob): Promise<Uint8Array> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    throw new Error("That file isn't an image PassAuth can read. Choose a JPEG, PNG or WebP picture.");
  }
  try {
    const { sx, sy, size } = squareCrop(bitmap.width, bitmap.height);
    const canvas = new OffscreenCanvas(AVATAR_SIZE, AVATAR_SIZE);
    const g = canvas.getContext("2d");
    if (!g || !size) throw new Error("That picture couldn't be used. Choose another image.");
    // JPEG has no transparency: transparent parts become white rather than black.
    g.fillStyle = "#fff";
    g.fillRect(0, 0, AVATAR_SIZE, AVATAR_SIZE);
    g.imageSmoothingQuality = "high";
    g.drawImage(bitmap, sx, sy, size, size, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
    return await encodeWithin((quality) => canvas.convertToBlob({ type: "image/jpeg", quality }));
  } finally {
    bitmap.close();
  }
}

/** Base64 of `bytes` in chunks (one spread of 256 KiB would be more arguments than a call takes). */
export function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
