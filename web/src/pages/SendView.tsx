import { useEffect, useMemo, useState, type FormEvent } from "react";
import * as core from "../wasm/passauth_core";
import { LogoMark } from "../components/Logo";
import { copyText, ErrorText, PasswordInput, SheetActions } from "../components/ui";
import { ApiError, UnreachableError, api, errorMessage, friendlyError } from "../lib/api";
import { sendKeys } from "../lib/send-kdf";
import { parseSendLocation, readOpenedSend, readPublicSend, visitorError, type PublicSend } from "../lib/sends";
import "../styles/files.css";

type Stage =
  | { kind: "loading" }
  | { kind: "problem"; title: string; text: string }
  | { kind: "ready"; info: PublicSend; name: string | null }
  | { kind: "open"; info: PublicSend; name: string; text: string };

const formatWhen = (seconds: number) => new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

const BAD_LINK = {
  title: "This link is incomplete",
  text: "The part after # is missing or damaged, and it holds the key that opens this Send. If you reloaded this page, open the link you were sent again; otherwise ask the person who sent it for the whole link.",
};
const WRONG_KEY = {
  title: "This link doesn't open this Send",
  text: "Part of the link may be missing or changed. Ask the person who sent it for the whole link, including the part after #.",
};
const GONE_TITLE = "This Send isn't available";

/** What went wrong, for the whole page (the password form shows a wrong password itself). */
function problem(e: unknown): { title: string; text: string } {
  if (e instanceof ApiError && e.status === 404) return { title: GONE_TITLE, text: visitorError(404, e.code) };
  if (e instanceof ApiError && e.status === 429) return { title: "Too many attempts", text: friendlyError(e) };
  if (e instanceof UnreachableError) return { title: "Can't reach the server", text: errorMessage(e) };
  if (e instanceof Error && e.message === "decrypt_failed") return WRONG_KEY;
  return { title: "PassAuth couldn't open this Send", text: friendlyError(e) };
}

/** The fragment taken from this page's address, with the path it came with (React may ask twice for the same one). */
let taken: { path: string; hash: string } | null = null;

/**
 * The page's fragment (`#<key>`), taken out of the address bar and this tab's history entry as soon as it is read, so
 * the Send's key doesn't stay on screen, in the tab's history or in synced tabs: from then on it is only in this page's
 * memory. (A browser may still have recorded the visit with its fragment in its own history list.)
 */
function takeFragment(): string {
  const hash = location.hash;
  if (hash && hash !== "#") {
    taken = { path: location.pathname, hash };
    try {
      // The router's own state is kept; only the address changes.
      history.replaceState(history.state, "", `${location.pathname}${location.search}`);
    } catch {
      /* the address stays as it is */
    }
    return hash;
  }
  return taken?.path === location.pathname ? taken.hash : "";
}

/**
 * The public page of a Send (`/send/<id>#<key>`), for anyone with the link, with or without an account. The key is read
 * from the fragment, which is then removed from the address (`takeFragment`), and never leaves this page: the server
 * gets only the id (and, for a Send with a password, a verifier derived from it on this device). The text is shown as
 * plain text, never as HTML.
 */
export function SendViewPage() {
  // The fragment can change without a page load (the whole link pasted into a tab that showed an incomplete one).
  const [hash, setHash] = useState(takeFragment);
  useEffect(() => {
    const changed = () => setHash(takeFragment());
    addEventListener("hashchange", changed);
    return () => removeEventListener("hashchange", changed);
  }, []);
  const { id, key } = useMemo(() => parseSendLocation(location.pathname, hash), [hash]);
  const [stage, setStage] = useState<Stage>({ kind: "loading" });
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  // The password's check (Argon2 with the Send's settings) is running: it can take a few seconds.
  const [checking, setChecking] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    setFormError(null);
    if (!id || !key) return setStage({ kind: "problem", ...BAD_LINK });
    setStage({ kind: "loading" });
    let live = true;
    (async () => {
      try {
        const info = readPublicSend(await api(`/public/sends/${encodeURIComponent(id)}`, { auth: false }));
        if (!info) throw new Error("The server sent an unexpected response. Reload the page to try again.");
        // Without a password the name comes first; it also proves the key fits before anything is opened.
        const name = info.name !== null ? core.sendOpen(key, null, "name", info.name) : null;
        if (live) setStage({ kind: "ready", info, name });
      } catch (e) {
        if (live) setStage({ kind: "problem", ...problem(e) });
      }
    })();
    return () => {
      live = false;
    };
  }, [id, key]);

  async function open(e?: FormEvent) {
    e?.preventDefault();
    if (stage.kind !== "ready" || !id || !key) return;
    const { info } = stage;
    if (info.needsPassword && !password) return setFormError("Enter the password the sender gave you.");
    setBusy(true);
    setFormError(null);
    try {
      let verifier: string | undefined;
      // A v2 Send's text opens only with this key (from the link key and the password); it never leaves this page.
      let contentKey: string | null = null;
      if (info.needsPassword && info.accessSalt) {
        // In a worker when it can be (`send-kdf.ts`): the page stays responsive and shows that it is working.
        setChecking(true);
        try {
          ({ verifier, contentKey } = await sendKeys(password, info.accessSalt, key));
        } finally {
          setChecking(false);
        }
      }
      const opened = readOpenedSend(
        await api(`/public/sends/${encodeURIComponent(id)}/access`, { method: "POST", auth: false, body: verifier ? { verifier } : {} }),
      );
      if (!opened) throw new Error("The server sent an unexpected response. Reload the page to try again.");
      // Either version: v1 with the link key alone, v2 with the content key too.
      const name = core.sendOpen(key, contentKey, "name", opened.name);
      const text = core.sendOpen(key, contentKey, "data", opened.data);
      setPassword("");
      setStage({ kind: "open", info, name, text });
    } catch (err) {
      setBusy(false);
      if (err instanceof ApiError && (err.status === 401 || err.code === "wrong_password")) return setFormError(visitorError(401, err.code));
      if (err instanceof ApiError && err.status === 429) return setFormError(friendlyError(err));
      // A salt outside what the core accepts: the Send's settings aren't ones this page will run.
      if (err instanceof Error && /salt|kdf|parameter/i.test(err.message)) return setFormError("This Send's password settings aren't ones PassAuth accepts. Ask the sender to make a new one.");
      setStage({ kind: "problem", ...problem(err) });
    }
  }

  const sender = stage.kind === "ready" || stage.kind === "open" ? stage.info.sender : null;
  const title =
    stage.kind === "open"
      ? stage.name
      : stage.kind === "ready"
        ? (stage.name ?? "Someone shared text with you")
        : stage.kind === "problem"
          ? stage.title
          : "Opening…";

  return (
    <main className="auth public-send">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={48} />
          <h1>{title}</h1>
          {sender && <p className="muted">Shared by {sender}</p>}
        </div>
        <div className="auth-panel stack">
          {stage.kind === "loading" && (
            <p className="muted" role="status">
              Opening…
            </p>
          )}
          {stage.kind === "problem" && (
            <p role="alert" className="card-text">
              {stage.text}
            </p>
          )}
          {stage.kind === "ready" && (
            <form className="stack" onSubmit={open}>
              {stage.info.needsPassword ? (
                <div className="field">
                  <label htmlFor="send-password">Password</label>
                  <PasswordInput id="send-password" value={password} onChange={setPassword} autoComplete="off" autoFocus />
                  <span className="field-hint">The sender protected this text with a password. They'll have told you some other way than the link.</span>
                </div>
              ) : (
                <p className="card-text">The text opens on this page. Opening it may count toward a limit the sender set on how often it can be opened.</p>
              )}
              {stage.info.expiresAt !== null && <p className="small muted">Available until {formatWhen(stage.info.expiresAt)}.</p>}
              {checking && (
                <div className="stack-s" role="status">
                  <div className="transfer-bar transfer-bar-busy" aria-hidden="true">
                    <i />
                  </div>
                  <span className="small muted">Checking the password. This can take a few seconds.</span>
                </div>
              )}
              <ErrorText error={formError} />
              <SheetActions>
                <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
                  {busy ? "Opening…" : "Open text"}
                </button>
              </SheetActions>
            </form>
          )}
          {stage.kind === "open" && (
            <>
              <div className="send-text" tabIndex={0} role="region" aria-label="Shared text">
                {stage.text}
              </div>
              <SheetActions>
                <button type="button" className="btn btn-primary btn-block" onClick={() => copyText(stage.text, "Text copied")}>
                  Copy text
                </button>
              </SheetActions>
              <p className="small muted">This page doesn't keep the text. Copy what you need before you close it.</p>
            </>
          )}
        </div>
        <p className="auth-foot">Shared with PassAuth. The text was encrypted on the sender's device; only this link opens it.</p>
      </div>
    </main>
  );
}
