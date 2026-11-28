// The Safari manifest (the extension inside the desktop app on macOS), made from the Chrome one (public/manifest.json) so
// they always list the same fill scripts and permissions. Safari runs the background as a non-persistent event
// page (background.scripts, with a DOM: background/clipboard.ts writes the clipboard itself). Left out: the passkey bridge and page shim (the desktop app's macOS AutoFill extension handles passkeys in
// Safari; two providers would mean two prompts), the offscreen page, the optional `privacy` permission (Safari has none),
// and Chrome-only keys. The right-click menu and the shortcuts stay; the fill shortcut gets its own key in Safari
// (SAFARI_KEYS). The version is the app's it ships in (build.mjs).

/** Safari 17, on macOS 14 (desktop/macos/project.yml), the oldest macOS the extension is built for. */
export const MIN_SAFARI = "17.0";

const DROP_KEYS = ["minimum_chrome_version", "externally_connectable", "optional_permissions"];
const DROP_PERMISSIONS = new Set(["offscreen"]);

/**
 * Shortcuts that differ in Safari. Safari's own Shift+Command+L is View → Show Sidebar (and Shift+Command+A is Edit →
 * AutoFill Form), and an extension's key takes the menu's place, so the fill shortcut is Shift+Command+P there. Safari
 * has no page for changing extension shortcuts, so these are the keys users get. Command+Shift+Y and +9 are free in Safari.
 */
export const SAFARI_KEYS = { autofill: "Command+Shift+P" };
const PASSKEY_SCRIPTS = new Set(["webauthn.js", "bridge.js"]);

export function safariManifest(chrome, version) {
  const m = structuredClone(chrome);
  for (const k of DROP_KEYS) delete m[k];
  m.version = version;
  for (const [name, key] of Object.entries(SAFARI_KEYS)) m.commands[name].suggested_key = { ...m.commands[name].suggested_key, mac: key };
  m.background = { scripts: [chrome.background.service_worker], type: chrome.background.type, persistent: false };
  // nativeMessaging: the sign-in hand-off from the PassAuth app (src/shared/app-handoff.ts).
  m.permissions = [...m.permissions.filter((p) => !DROP_PERMISSIONS.has(p)), "nativeMessaging"];
  m.content_scripts = m.content_scripts.filter((c) => !c.js.some((js) => PASSKEY_SCRIPTS.has(js))).map(({ match_origin_as_fallback: _, ...rest }) => rest);
  m.web_accessible_resources = m.web_accessible_resources.map(({ use_dynamic_url: _, ...rest }) => rest);
  m.browser_specific_settings = { safari: { strict_min_version: MIN_SAFARI } };
  return m;
}
