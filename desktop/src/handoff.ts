/**
 * macOS: leave the AutoFill extension what it needs to sign in as its own device (server address,
 * email, remembered Secret Key; never tokens or vault keys) in its Keychain access group, whenever the
 * vault is unlocked. The extension then asks only for the master password. Cleared on "Change server".
 */
import { invoke } from "@tauri-apps/api/core";
import { secretStore } from "@web/lib/platform";
import { EMAIL_KEY, getState, onVaultChange, rememberedSecretKey } from "@web/lib/vault";
import { savedServer } from "./server";

const isMac = navigator.platform.startsWith("Mac");
let written = "";

function update() {
  if (getState().status !== "unlocked") return;
  const server = savedServer();
  const email = secretStore.get(EMAIL_KEY);
  if (!server || !email) return;
  const payload = { server, email, secretKey: rememberedSecretKey(email) };
  const key = JSON.stringify(payload);
  if (key === written) return;
  written = key;
  invoke("autofill_handoff", payload).catch(() => {
    written = "";
  });
}

export function installAutofillHandoff() {
  if (!isMac) return;
  onVaultChange(update);
}

export async function clearAutofillHandoff() {
  if (!isMac) return;
  written = "";
  await invoke("autofill_handoff_clear").catch(() => {});
}
