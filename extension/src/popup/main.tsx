import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@web/styles/app.css";
import "./popup.css";

import { Component, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { fluidPopup, isSafari } from "../shared/browser";
import { POPUP_WINDOW } from "../shared/windows";
import { App } from "./App";
import { fitWindow } from "./fit-window";
import { PasskeyConfirm } from "./Passkey";
import { loadTheme } from "./theme";
import { Welcome } from "./welcome";

const welcome = new URLSearchParams(location.search).has("welcome");

// Lets the background run the "Immediately" vault timeout when the popup closes.
// The heartbeat keeps the service worker awake while a PassAuth window is open
// (e.g. a passkey confirmation); if the worker was stopped anyway, reconnect.
// The welcome tab is no PassAuth window: it never holds the vault open.
function keepAlive() {
  const port = chrome.runtime.connect({ name: "popup" });
  const beat = setInterval(() => port.postMessage("beat"), 20_000);
  port.onDisconnect.addListener(() => {
    clearInterval(beat);
    setTimeout(keepAlive, 100);
  });
}
if (!welcome) keepAlive();

const passkey = location.hash.match(/^#passkey=(.+)$/)?.[1];
const popout = new URLSearchParams(location.search).has("popout");
if (popout) document.documentElement.classList.add("popout");
if (fluidPopup(isSafari(), matchMedia("(pointer: coarse)").matches)) document.documentElement.classList.add("fluid");
if (welcome) document.documentElement.classList.add("welcome-page");
// The confirmation window is exactly as tall as its sheet (Passkey.tsx sizes it).
if (passkey) document.documentElement.classList.add("sheet-window");
/** Anything a page throws while drawing ends here, with a way out, instead of an empty window. */
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="pop-auth" role="alert">
        <div className="auth-head">
          <h1>Something went wrong</h1>
          <p className="auth-sub">PassAuth couldn't show this page. Your vault is not affected.</p>
        </div>
        <p className="alert alert-error small">{this.state.error.message}</p>
        <button type="button" className="btn btn-primary btn-block" onClick={() => location.reload()}>
          Reload PassAuth
        </button>
      </div>
    );
  }
}

await loadTheme();
createRoot(document.getElementById("root")!).render(<ErrorBoundary>{welcome ? <Welcome /> : passkey ? <PasskeyConfirm requestId={passkey} /> : <App />}</ErrorBoundary>);
// PassAuth in its own window (pop-out, unlock): the page area the popup was designed for, whatever the OS frame is.
if (popout && !passkey) void fitWindow(() => POPUP_WINDOW);
