import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { Icon, SheetActions, SiteIcon } from "@web/components/ui";
import { NEW_LOGIN } from "../background/save-plan";
import { send } from "../shared/messages";
import { fitWindow } from "../shared/windows";
import { BrandBar, Choices, Context, OnlyChoice, Tile, type Choice } from "./sheet";

/** Accepting (the primary button, Enter) only counts once the sheet has been on screen this long. */
const ACCEPT_DELAY_MS = 500;

/** Page width of the confirmation window (background/passkey-handler.ts opens it at this width). */
const SHEET_WIDTH = 380;

interface Info {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string; preferred?: boolean; vault?: string }[];
  /** The site requires user verification: confirm with the master password. */
  needsPassword: boolean;
  /** For the site icon. */
  server: string;
  showIcons: boolean;
}

/**
 * Keep the window exactly as tall as the sheet: it opens at an estimate, and
 * grows or shrinks when the content does (an error message, a wrapped line).
 */
function useFitWindow(ready: boolean) {
  useLayoutEffect(() => {
    // #root is exactly as tall as the sheet in this window (popup.css `html.sheet-window`).
    const el = document.getElementById("root");
    if (!ready || !el) return;
    const fit = () => void fitWindow(() => ({ width: SHEET_WIDTH, height: Math.ceil(el.getBoundingClientRect().height) })).then(() => document.documentElement.classList.add("fitted"));
    fit();
    const observer = new ResizeObserver(fit);
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
  useFitWindow(info !== undefined);
  /** When the sheet with its choices was first drawn. */
  const shownAt = useRef(Infinity);

  useEffect(() => {
    send<Info | null>({ type: "passkey:pending", requestId }).then(
      (i) => {
        setInfo(i);
        // Saving: the best matching login for this exact site is preselected, else a new login.
        setChoice(i?.kind === "create" ? (i.candidates.find((c) => c.preferred)?.credentialId ?? NEW_LOGIN) : i?.candidates[0]?.credentialId);
      },
      () => setInfo(null),
    );
  }, [requestId]);

  const decide = async (accept: boolean, fallback = false) => {
    if (busy) return;
    // A click or key press that was already on its way when the window appeared must not confirm anything.
    if (accept && performance.now() - shownAt.current < ACCEPT_DELAY_MS) return;
    setBusy(true);
    setError("");
    try {
      await send({ type: "passkey:decide", requestId, accept, credentialId: choice, fallback, password: accept && info?.needsPassword ? password : undefined });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  const decideRef = useRef(decide);
  decideRef.current = decide;

  // Escape cancels, as in any dialog. Focus starts where the keyboard is most useful:
  // the password field, else the selected row (arrows move, Enter confirms), else the primary button.
  const loaded = !!info;
  useEffect(() => {
    if (!loaded) return;
    shownAt.current = performance.now();
    document.querySelector<HTMLElement>('input[type="password"], input[type="radio"]:checked, button[type="submit"]')?.focus();
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
    <form className="sheet" onSubmit={submit} onKeyDown={onKeyDown} aria-busy={busy}>
      <BrandBar />
      <div className="modal-body">
        <Context icon={<SiteIcon host={info.rpId} name={info.rpId} server={info.server} enabled={info.showIcons && !!info.server} />} title={creating ? "Save a passkey" : "Sign in with a passkey"} sub={info.rpId} />
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
    </form>
  );
}
