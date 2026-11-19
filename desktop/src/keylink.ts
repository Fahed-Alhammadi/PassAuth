/**
 * Two-step login with a security key: the sign-in page opens the server's key page in the browser, which hands the
 * signed assertion back as a `passauth://two-step-key#…` link (scheme in tauri.conf.json; lib.rs brings the window up).
 * Every such link goes to the web vault's waiter, which takes it only while a sign-in waits, only once, and only for the
 * challenge it opened (web/src/lib/key-page.ts). A link that started the app is ignored: nothing can be waiting then.
 */
import { onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { APP_RETURN, keyPageWaiter } from "@web/lib/key-page";

const PREFIX = APP_RETURN.toLowerCase();

export async function installKeyPageLinks() {
  await onOpenUrl((urls) => {
    for (const url of urls) {
      if (url.toLowerCase().startsWith(PREFIX)) keyPageWaiter.deliver(url);
    }
  });
}
