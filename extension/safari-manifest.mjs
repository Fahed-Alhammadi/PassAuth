// The Safari manifest (the extension in the "PassAuth for Safari" app, iPhone/iPad/Mac), made from the Chrome one (public/manifest.json) so
// they always list the same fill scripts and permissions. Safari runs the background as a non-persistent event
// page (background.scripts, with a DOM: background/clipboard.ts writes the clipboard itself), and iOS stops it at any
// time. Left out: the passkey bridge and page shim (the iOS AutoFill extension handles passkeys in Safari; two
// providers would mean two prompts), the offscreen page, the right-click menu, shortcuts and the optional `privacy`
// permission (Safari on iOS has none of them), and Chrome-only keys. The version is the Safari app's (safari/VERSION):
// the extension ships inside that app.

/** Safari 17 (iOS 17, macOS 14), the Safari app's deployment targets (safari/project.yml). */
export const MIN_SAFARI = "17.0";

const DROP_KEYS = ["minimum_chrome_version", "externally_connectable", "commands", "optional_permissions"];
const DROP_PERMISSIONS = new Set(["offscreen", "contextMenus"]);
const PASSKEY_SCRIPTS = new Set(["webauthn.js", "bridge.js"]);

export function safariManifest(chrome, version) {
  const m = structuredClone(chrome);
  for (const k of DROP_KEYS) delete m[k];
  m.version = version;
  m.background = { scripts: [chrome.background.service_worker], type: chrome.background.type, persistent: false };
  // nativeMessaging: the sign-in hand-off from the PassAuth app (src/shared/app-handoff.ts).
  m.permissions = [...m.permissions.filter((p) => !DROP_PERMISSIONS.has(p)), "nativeMessaging"];
  m.content_scripts = m.content_scripts.filter((c) => !c.js.some((js) => PASSKEY_SCRIPTS.has(js))).map(({ match_origin_as_fallback: _, ...rest }) => rest);
  m.web_accessible_resources = m.web_accessible_resources.map(({ use_dynamic_url: _, ...rest }) => rest);
  m.browser_specific_settings = { safari: { strict_min_version: MIN_SAFARI } };
  return m;
}
