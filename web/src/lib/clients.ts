/**
 * Apps by the name they send in `X-PassAuth-Client` (`<name>/<version>`), for Signed-in devices and the activity log.
 * Pure (no React): the icons are names from `components/ui.tsx`.
 */
import { oneLine } from "./text";

export type ClientIcon = "globe" | "desktop" | "puzzle" | "phone" | "terminal";

/** `version: false` leaves the version out. */
const CLIENTS = new Map<string, { label: string; icon: ClientIcon; version?: false }>([
  ["web", { label: "Web", icon: "globe", version: false }],
  ["desktop", { label: "Desktop app", icon: "desktop" }],
  ["extension", { label: "Chrome extension", icon: "puzzle" }],
  ["chrome", { label: "Chrome extension", icon: "puzzle" }],
  ["chrome-extension", { label: "Chrome extension", icon: "puzzle" }],
  ["ios", { label: "iPhone app", icon: "phone" }],
  ["iphone", { label: "iPhone app", icon: "phone" }],
  ["ipad", { label: "iPad app", icon: "phone" }],
  ["ios-autofill", { label: "iPhone AutoFill", icon: "phone" }],
  ["android", { label: "Android app", icon: "phone" }],
  ["macos-autofill", { label: "Mac AutoFill", icon: "desktop" }],
  ["mac-autofill", { label: "Mac AutoFill", icon: "desktop" }],
  ["cli", { label: "Command line", icon: "terminal" }],
]);

const KINDS: Record<string, { label: string; icon: ClientIcon }> = {
  web: { label: "Web vault", icon: "globe" },
  extension: { label: "Browser extension", icon: "puzzle" },
  cli: { label: "Command line", icon: "terminal" },
  desktop: { label: "Desktop app", icon: "desktop" },
  mobile: { label: "Mobile app", icon: "phone" },
};

/** A device's kind as the apps send it at sign-in ("web", "mobile"…): "Web vault", "Mobile app"; other kinds as written. */
export function deviceKindInfo(kind: string): { label: string; icon: ClientIcon | null } {
  const known = Object.hasOwn(KINDS, kind) ? KINDS[kind] : undefined;
  if (known) return known;
  // Claimed by the device: one line, no control or format characters (bidi overrides could disguise it).
  const k = oneLine(kind, 40);
  return { label: k ? `${k.charAt(0).toUpperCase()}${k.slice(1)}` : "Device", icon: null };
}

/** "desktop/0.7.0" → "Desktop app 0.7.0", "web/0.9.0" → "Web"; null when there is no client (older servers and sessions). */
export function clientInfo(client: string | null | undefined): { label: string; icon: ClientIcon | null } | null {
  // Claimed by the app that signed in: one line, no control or format characters.
  const raw = oneLine(client, 80);
  if (!raw) return null;
  const slash = raw.indexOf("/");
  const name = (slash < 0 ? raw : raw.slice(0, slash)).toLowerCase().replace(/[\s_]+/g, "-");
  const version = slash < 0 ? "" : raw.slice(slash + 1).trim();
  const shownVersion = /^\d[\w.+-]{0,31}$/.test(version) ? version : "";
  const known = CLIENTS.get(name);
  if (!known) {
    const label = name.slice(0, 40);
    return label ? { label: `${label.charAt(0).toUpperCase()}${label.slice(1)}${shownVersion ? ` ${shownVersion}` : ""}`, icon: null } : null;
  }
  return { label: known.version === false || !shownVersion ? known.label : `${known.label} ${shownVersion}`, icon: known.icon };
}
