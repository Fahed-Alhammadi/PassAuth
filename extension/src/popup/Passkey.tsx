import { Icon, SheetActions, SiteIcon } from "@web/components/ui";
import { type FormEvent, type KeyboardEvent, useEffect, useLayoutEffect, useRef, useState } from "react";
import { codeOf, PASSWORD_REQUIRED } from "../shared/errors";
import { callPasskeyWindow } from "../shared/protocol";
import { NEW_LOGIN, sharedWarning } from "../shared/save-text";
import type { PasskeyRequestInfo } from "../shared/types";
import { fitWindow } from "./fit-window";
import { BrandBar, type Choice, Choices, Context, OnlyChoice, Tile } from "./sheet";

/** Accepting (the primary button, Enter) only counts once the sheet has been on screen this long. */
const ACCEPT_DELAY_MS = 500;

/** Page width of the confirmation window (background/passkey-handler.ts opens it at this width). */
const SHEET_WIDTH = 380;

type Info = PasskeyRequestInfo;

/**
 * Keep the window exactly as tall as the sheet: it opens at an estimate, and
 * grows or shrinks when the content does (an error message, a wrapped line).
 */
function useFitWindow(ready: boolean) {
  useLayoutEffect(() => {
    // #root is exactly as tall as the sheet in this window (popup.css `html.sheet-window`).
    const el = document.getElementById("root");
    if (!ready || !el) return;
    const fitToSheet = () => void fitWindow(() => ({ width: SHEET_WIDTH, height: Math.ceil(el.getBoundingClientRect().height) })).then(() => document.documentElement.classList.add("fitted"));
    fitToSheet();
    const observer = new ResizeObserver(fitToSheet);
    observer.observe(el);
    return () => observer.disconnect();
  }, [ready]);
}

/** Confirmation window for passkey creation and sign-in. */
export function PasskeyConfirm({ requestId }: { requestId: string }) {
  const [info, setInfo] = useState<Info | null | undefined>(undefined);
  const [choice, setChoice] = useState<string | undefined>();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  /** "Click again" (or "Press Enter again", "Tap again"): an accept that came too soon after the window appeared. */
  const [hint, setHint] = useState("");
  const hintTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  /** The last kind of input in this window, for the hint's words. */
  const lastInput = useRef<"key" | "mouse" | "touch">("mouse");
  useFitWindow(info !== undefined);
  /** When the sheet with its choices was first drawn. */
  const shownAt = useRef(Infinity);
  useEffect(() => {
    const onPointer = (e: PointerEvent) => (lastInput.current = e.pointerType === "touch" || e.pointerType === "pen" ? "touch" : "mouse");
    const onKey = () => (lastInput.current = "key");
    addEventListener("pointerdown", onPointer, true);
    addEventListener("keydown", onKey, true);
    return () => {
      removeEventListener("pointerdown", onPointer, true);
      removeEventListener("keydown", onKey, true);
      clearTimeout(hintTimer.current);
    };
  }, []);

  useEffect(() => {
    callPasskeyWindow("passkey:pending", { requestId }).then(
      (i) => {
        setInfo(i);
        // Saving: the user's own login for this exact site is preselected (the core's choice), else a new login.
        setChoice(i?.kind === "create" ? (i.candidates.some((c) => c.credentialId === i.selected) ? i.selected : NEW_LOGIN) : i?.candidates[0]?.credentialId);
      },
      () => setInfo(null),
    );
  }, [requestId]);

  const decide = async (accept: boolean, fallback = false) => {
    if (busy) return;
    // A click or key press that was already on its way when the window appeared must not confirm anything: say so,
    // so a quick but deliberate click isn't simply lost.
    if (accept && performance.now() - shownAt.current < ACCEPT_DELAY_MS) {
      setHint(lastInput.current === "key" ? "Press Enter again" : lastInput.current === "touch" ? "Tap again" : "Click again");
      clearTimeout(hintTimer.current);
      hintTimer.current = setTimeout(() => setHint(""), 2000);
      return;
    }
    setHint("");
    setBusy(true);
    setError("");
    try {
      await callPasskeyWindow("passkey:decide", { requestId, accept, credentialId: choice, fallback, password: accept && info?.needsPassword ? password : undefined });
    } catch (e) {
      // The site requires user verification and the last master-password entry is too old now: ask for it here.
      if (codeOf(e) === PASSWORD_REQUIRED && info && !info.needsPassword) setInfo({ ...info, needsPassword: true });
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  const decideRef = useRef(decide);
  decideRef.current = decide;

  // Escape cancels, as in any dialog. Focus starts on the password field when there is one, else on the
  // sheet itself (never on a button or a choice, where a key press already on its way could confirm).
  const loaded = !!info;
  useEffect(() => {
    if (!loaded) return;
    shownAt.current = performance.now();
    (document.querySelector<HTMLElement>('input[type="password"]') ?? document.querySelector<HTMLElement>("form.sheet"))?.focus({ preventScroll: true });
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") void decideRef.current(false);
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [loaded]);

  if (info === undefined) return null;
  if (!info) {
    return (
      <div className="sheet">
        <BrandBar />
        <div className="modal-body">
          <Context
            icon={
              <Tile>
                <Icon name="info" size={20} />
              </Tile>
            }
            title="This request has expired"
            sub="Go back to the website and try again."
          />
          <SheetActions>
            <button type="button" className="btn btn-primary btn-block" autoFocus onClick={() => window.close()}>
              Close
            </button>
          </SheetActions>
        </div>
      </div>
    );
  }

  const creating = info.kind === "create";
  const chosen = creating ? info.candidates.find((c) => c.credentialId === choice) : undefined;
  // A login in a shared vault is never preselected; when the user picks one, say who else gets the passkey.
  const shared = chosen?.vault ? sharedWarning({ id: chosen.credentialId, name: chosen.itemName, username: chosen.userName, vault: chosen.vault }, "passkey") : null;
  const options: Choice[] = creating
    ? [
        // A login in a shared vault is never preselected and says which vault: its members get the passkey too.
        ...info.candidates.map((c) => {
          const user = c.userName || "No user name";
          return { id: c.credentialId, title: c.itemName, sub: c.vault ? `In ${c.vault}: ${user}` : user, icon: <Tile name={c.itemName} /> };
        }),
        {
          id: NEW_LOGIN,
          title: "New login",
          sub: info.rpId,
          icon: (
            <Tile>
              <Icon name="plus" />
            </Tile>
          ),
        },
      ]
    : info.candidates.map((c) => ({ id: c.credentialId, title: c.userName || "Passkey", sub: c.itemName, icon: <Tile name={c.userName || c.itemName} /> }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void decide(true);
  };
  // Enter on the selected row confirms it, like Enter in a text field.
  const onKeyDown = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "radio") {
      e.preventDefault();
      e.currentTarget.requestSubmit();
    }
  };

  return (
    <form className="sheet" onSubmit={submit} onKeyDown={onKeyDown} aria-busy={busy} aria-label={creating ? "Save a passkey" : "Sign in with a passkey"} tabIndex={-1}>
      <BrandBar />
      <div className="modal-body">
        <Context
          icon={<SiteIcon host={info.rpId} name={info.rpId} server={info.server} enabled={info.showIcons && !!info.server} />}
          title={creating ? "Save a passkey" : "Sign in with a passkey"}
          sub={info.rpId}
        />
        {creating && (
          <p className="sheet-note">
            {info.userName ? (
              <>
                Creates a passkey for <strong>{info.userName}</strong>.{" "}
              </>
            ) : null}
            It is stored encrypted in your vault and works on every device where you use PassAuth.
          </p>
        )}
        {creating ? (
          // Without a login for this site there is nothing to choose: the passkey goes into a new one.
          info.candidates.length > 0 && <Choices label="Save in" options={options} value={choice} onChange={setChoice} disabled={busy} />
        ) : options.length > 1 ? (
          <Choices label="Choose an account" options={options} value={choice} onChange={setChoice} disabled={busy} />
        ) : (
          options[0] && <OnlyChoice label="Account" choice={options[0]} />
        )}
        {shared && (
          <p className="alert alert-warn" role="status">
            {shared.map((part, i) =>
              typeof part === "string" ? (
                part
              ) : (
                // biome-ignore lint/suspicious/noArrayIndexKey: the parts of one fixed sentence, never reordered
                <strong key={i}>{part.strong}</strong>
              ),
            )}
          </p>
        )}
        {error && (
          <p className="alert alert-error" role="alert">
            {error}
          </p>
        )}
        {info.needsPassword && (
          <div className="field">
            <label htmlFor="pk-password">Master password</label>
            <input
              id="pk-password"
              className="input mono"
              type="password"
              autoComplete="current-password"
              aria-describedby="pk-reason"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
              autoFocus
              required
            />
            <span id="pk-reason" className="field-hint">
              {info.rpId} asks PassAuth to confirm it's you.
            </span>
          </div>
        )}
        <SheetActions
          quiet={
            <>
              <button type="button" className="btn btn-text" disabled={busy} onClick={() => decide(false, true)}>
                Use a security key or another device
              </button>
              <button type="button" className="btn btn-text" disabled={busy} onClick={() => decide(false)}>
                Cancel
              </button>
            </>
          }
        >
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {creating ? (busy ? "Saving passkey…" : "Save passkey") : busy ? "Signing in…" : "Sign in"}
          </button>
        </SheetActions>
      </div>
      {/* Over the bottom of the sheet: it never changes the window's size. */}
      <p className={hint ? "again-hint show" : "again-hint"} role="status">
        {hint}
      </p>
    </form>
  );
}
