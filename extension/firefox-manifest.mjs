// The Firefox manifest, made from the Chrome one (public/manifest.json) so both always list the same scripts,
// permissions and commands. Firefox runs the background as an event page (background.scripts) instead of a service
// worker, has no offscreen documents (its background writes the clipboard itself, background/clipboard.ts), needs a
// fixed add-on id, and asks every new add-on to declare what data it sends out of the browser.

/** The add-on id on addons.mozilla.org. It can never change once the first version is uploaded. */
export const GECKO_ID = "passauth@fahed-alhammadi.github.io";

/** Firefox 140 (ESR): MAIN-world content scripts (128), storage.session, data_collection_permissions. */
export const MIN_FIREFOX = "140.0";

/** Keys Firefox doesn't support; it would only warn about them. */
const CHROME_ONLY_KEYS = ["minimum_chrome_version", "externally_connectable"];
const CHROME_ONLY_PERMISSIONS = new Set(["offscreen"]);

export function firefoxManifest(chrome) {
  const m = structuredClone(chrome);
  for (const k of CHROME_ONLY_KEYS) delete m[k];
  m.background = { scripts: [chrome.background.service_worker], type: chrome.background.type };
  m.permissions = m.permissions.filter((p) => !CHROME_ONLY_PERMISSIONS.has(p));
  m.web_accessible_resources = m.web_accessible_resources.map(({ use_dynamic_url: _, ...rest }) => rest);
  m.browser_specific_settings = {
    gecko: {
      id: GECKO_ID,
      strict_min_version: MIN_FIREFOX,
      // The vault (end-to-end encrypted logins) and the account email go to the PassAuth server the user signs in to.
      data_collection_permissions: { required: ["authenticationInfo", "personallyIdentifyingInfo"] },
    },
  };
  return m;
}
