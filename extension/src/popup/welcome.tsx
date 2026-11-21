/**
 * The welcome tab after a first install (popup.html?welcome=1, opened by background/main.ts): pin the extension,
 * connect a server, the keyboard shortcuts, the default-manager setting and importing. Short on purpose.
 */

import { LogoMark } from "@web/components/Logo";
import { Icon, type IconName } from "@web/components/ui";
import { type ReactNode, useEffect, useState } from "react";
import { browserFeatures, browserName, isFirefox, isSafari } from "../shared/browser";
import { DefaultManager, Shortcuts } from "./settings";

function Step({ n, icon, title, children }: { n: number; icon: IconName; title: string; children: ReactNode }) {
  return (
    <li className="welcome-step card-box">
      <span className="tile" aria-hidden="true">
        <Icon name={icon} size={20} />
      </span>
      <div className="grow stack-s">
        <h2>
          <span className="sr-only">Step {n}: </span>
          {title}
        </h2>
        {children}
      </div>
    </li>
  );
}

const STEP_WORDS = ["", "One", "Two", "Three", "Four", "Five"];

export function Welcome() {
  // Safari has no shortcuts and no browser password manager setting: those steps are left out.
  const features = browserFeatures();
  const [server, setServer] = useState("");
  const [note, setNote] = useState("");
  useEffect(() => {
    document.title = "Welcome to PassAuth";
    // The active account's server, once one is connected (the popup writes it).
    const read = () =>
      chrome.storage.local.get(["accounts", "active"]).then(
        (r) => setServer(((r.accounts as Record<string, { server?: string }> | undefined)?.[r.active as string]?.server as string | undefined) ?? ""),
        () => {},
      );
    void read();
    chrome.storage.onChanged.addListener(read);
    return () => chrome.storage.onChanged.removeListener(read);
  }, []);

  async function openPassAuth() {
    try {
      await chrome.action.openPopup();
    } catch {
      setNote("Click the PassAuth icon in the toolbar (pin it first, see step 1).");
    }
  }

  return (
    <main className="welcome">
      <header className="welcome-head">
        <LogoMark size={56} />
        <h1>Welcome to PassAuth</h1>
        <p className="muted">{STEP_WORDS[3 + Number(features.shortcuts) + Number(features.defaultPasswordManager)]} short steps and your passwords are ready to fill.</p>
      </header>
      <ol className="welcome-steps">
        <Step n={1} icon="puzzle" title="Pin PassAuth to the toolbar">
          <p>
            {isSafari()
              ? "In Safari, choose Safari → Settings → Extensions and turn on PassAuth: it appears in the toolbar."
              : isFirefox()
                ? "Click the puzzle piece in Firefox's toolbar, then the gear next to PassAuth and Pin to Toolbar, so it is always one click away."
                : `Click the puzzle piece in ${browserName()}'s toolbar, then the pin next to PassAuth, so it is always one click away.`}
          </p>
        </Step>
        <Step n={2} icon="globe" title="Connect to your server">
          <p>Open PassAuth, enter your PassAuth server's address and sign in with your email, master password and, if you use one, your Secret Key.</p>
          <div>
            <button type="button" className="btn btn-primary" onClick={() => void openPassAuth()}>
              Open PassAuth
            </button>
          </div>
          {note && (
            <p className="small muted" role="status">
              {note}
            </p>
          )}
        </Step>
        {features.shortcuts && (
          <Step n={3} icon="wand" title="Fill with the keyboard">
            <Shortcuts />
          </Step>
        )}
        {features.defaultPasswordManager && (
          <Step n={features.shortcuts ? 4 : 3} icon="shield" title="Make PassAuth your default password manager">
            <DefaultManager notify={setNote} />
          </Step>
        )}
        <Step n={2 + Number(features.shortcuts) + Number(features.defaultPasswordManager) + 1} icon="upload" title="Bring your passwords">
          <p>Import from another password manager in the PassAuth web vault, under Tools → Import. The file is read on your device; only encrypted items reach your server.</p>
          {server && (
            <div>
              <button type="button" className="btn" onClick={() => void chrome.tabs.create({ url: `${server}/import` })}>
                <Icon name="external" /> Open the web vault's import page
              </button>
            </div>
          )}
        </Step>
      </ol>
    </main>
  );
}
