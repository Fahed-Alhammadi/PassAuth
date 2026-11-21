/**
 * Safari only: the server, email and Secret Key another PassAuth app on this device left for this extension's sign-in
 * (iPhone/iPad: the PassAuth app; Mac: the desktop app), asked from the "PassAuth for Safari" app's native handler
 * (safari/Extension/Handoff.swift). Never tokens or keys: the extension still signs in itself with the master password.
 */
import { isSafari } from "./browser";

export interface AppHandoff {
  server: string;
  email: string;
  secretKey?: string;
}

/** The app the native messages go to (Safari ignores the name and asks the extension's own app). */
const NATIVE_APP = "io.passauth.safari";

/** The hand-off, or null (not Safari, none left, or an answer that isn't one). */
export async function appHandoff(): Promise<AppHandoff | null> {
  if (!isSafari()) return null;
  const send = (chrome.runtime as { sendNativeMessage?: (app: string, message: unknown) => Promise<unknown> }).sendNativeMessage;
  if (typeof send !== "function") return null;
  const r = (await send.call(chrome.runtime, NATIVE_APP, { type: "handoff" }).catch(() => null)) as Record<string, unknown> | null;
  if (!r || typeof r !== "object") return null;
  const { server, email, secretKey } = r;
  if (typeof server !== "string" || !/^https?:\/\//.test(server) || typeof email !== "string" || !email) return null;
  return { server, email, ...(typeof secretKey === "string" && secretKey ? { secretKey } : {}) };
}
