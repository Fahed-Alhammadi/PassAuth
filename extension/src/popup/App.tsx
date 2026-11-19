import { LogoMark } from "@web/components/Logo";
import { ConfirmDialog, ErrorText, Icon, PasswordInput, SheetActions } from "@web/components/ui";
import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { codeOf, LOCKED, SECRET_KEY_REQUIRED, SIGNED_OUT, TWO_STEP_REQUIRED } from "../shared/errors";
import { callPopup, setFailureHandler } from "../shared/protocol";
import type { PopupState, TwoFactorChallenge } from "../shared/types";
import { openCentered, POPUP_WINDOW } from "../shared/windows";
import { AddSitePage } from "./add-site";
import { type CopyRequest, type Ctx, hostOf, KEY_PAGE_TEXT, KEY_PAGE_WARNING, msg, PROVIDER_ICONS, PROVIDER_TITLES, type Route, seconds } from "./ctx";
import { DeviceSignIn, deviceSignInEmail, deviceSignInUrl } from "./device-sign-in";
import { EditPage } from "./editor";
import { GeneratorPage } from "./generator";
import { HistoryPage, ItemPage } from "./item";
import { SettingsPage } from "./settings";
import { Choices, Tile } from "./sheet";
import { OtherAccounts } from "./shell";
import { ClosedNote, CodeNote, SignInSheet, useSignIns } from "./sign-in-requests";
import { VaultList } from "./vault";
import { dropPendingView, flushView, LIST, type ListFilter, NO_FILTER, type Start, saveView, takeStart, vaultChanged } from "./view-state";

/** Copies through the background, which also clears the clipboard after the user's delay (even once the popup closes). */
const copiedNote = (label: string, clearAfter: number) => `${label} copied.${clearAfter ? ` Clipboard clears in ${seconds(clearAfter)}.` : ""}`;

export function App() {
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** A note for the vault screen (a fill that waited for the unlock and didn't work). */
  const [startNote, setStartNote] = useState<string | undefined>();
  const reload = useCallback(() => callPopup("state").then(setState, (e) => setError(msg(e))), []);
  useEffect(() => void reload(), [reload]);
  // Locked by the timeout, signed out by the server, or the server requires two-step login first, while this window
  // was open: show the screen for that (unlock, sign in, set up two-step login) instead of an error on the page that asked.
  useEffect(() => {
    setFailureHandler((e) => {
      if (e.code === LOCKED || e.code === SIGNED_OUT || e.code === TWO_STEP_REQUIRED) void reload();
    });
    return () => setFailureHandler(() => {});
  }, [reload]);

  if (!state) return <div className="pop-auth">{error ? <ErrorText error={error} /> : null}</div>;
  // Keyed by account so switching accounts starts each screen fresh.
  const others = <OtherAccounts state={state} onChange={reload} />;
  const screen = (body: ReactNode) => (
    <div key={state.activeId}>
      {body}
      {others}
    </div>
  );
  if (state.status === "setup") return screen(<Setup onDone={reload} />);
  if (state.status === "logged-out")
    return screen(
      <Login
        state={state}
        onDone={(note) => {
          setStartNote(note);
          void reload();
        }}
      />,
    );
  if (state.status === "locked")
    return screen(
      <Unlock
        state={state}
        onDone={(note) => {
          setStartNote(note);
          void reload();
        }}
      />,
    );
  if (state.twoStepRequired) return screen(<TwoStepRequired state={state} onDone={reload} />);
  return <Main key={state.activeId} state={state} onChange={reload} startNote={startNote} />;
}

/**
 * The server requires two-step login and this account has no method yet (403 `two_step_required`): nothing but
 * setting one up (in the web vault) and signing out works. PassAuth asks the server again each time the popup opens,
 * or with "Check again".
 */
function TwoStepRequired({ state, onDone }: { state: PopupState; onDone: () => Promise<unknown> | undefined }) {
  const [signingOut, setSigningOut] = useState(false);
  const [checking, setChecking] = useState(false);
  return (
    <div className="pop-auth">
      <AuthHead title="Your server requires two-step login" sub={state.email} />
      <p className="card-text">Set up an authenticator app, email codes or a security key in the web vault, under Settings → Two-step login. Then come back here: your vault opens as usual.</p>
      <SheetActions
        quiet={
          <>
            <button
              type="button"
              className="btn btn-text"
              disabled={checking}
              onClick={() => {
                setChecking(true);
                void Promise.resolve(onDone()).finally(() => setChecking(false));
              }}
            >
              {checking ? "Checking…" : "Check again"}
            </button>
            <button type="button" className="btn btn-text" onClick={() => setSigningOut(true)}>
              Sign out…
            </button>
          </>
        }
      >
        <button type="button" className="btn btn-primary btn-block" onClick={() => void chrome.tabs.create({ url: `${state.server}/settings/two-step` })}>
          Set it up in the web vault
        </button>
      </SheetActions>
      {signingOut && <SignOutDialog state={state} onClose={() => setSigningOut(false)} onDone={() => void onDone()} />}
    </div>
  );
}

/** What signing in again takes, said before signing out (it also forgets this browser's Secret Key and two-step pass). */
export function SignOutDialog({ state, onClose, onDone }: { state: PopupState; onClose: () => void; onDone: () => void }) {
  const needs = ["your master password"];
  if (state.secretKeyRequired) needs.push("your Secret Key (it is in your Emergency Kit)");
  needs.push(state.rememberedDevice ? "a two-step login code (this browser no longer skips it)" : "a two-step login code, if your account uses two-step login");
  const list = needs.length > 1 ? `${needs.slice(0, -1).join(", ")} and ${needs.at(-1)}` : needs[0];
  return (
    <ConfirmDialog
      title={`Sign out of ${state.email}?`}
      subtitle={hostOf(state.server)}
      icon="logout"
      action="Sign out"
      busyAction="Signing out…"
      onClose={onClose}
      onConfirm={async () => {
        await callPopup("logout");
        onDone();
      }}
    >
      <p className="card-text">PassAuth removes this account's vault from this browser. To sign in again you need {list}.</p>
    </ConfirmDialog>
  );
}

/** Lock screen, sign-in and setup share one centred header: the mark, what to do, and for which account or server. */
function AuthHead({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="auth-head">
      <LogoMark size={48} />
      <h1>{title}</h1>
      {sub && <p className="auth-sub">{sub}</p>}
    </div>
  );
}

// ------------------------------------------------------------------ setup

function Setup({ onDone, initial = "" }: { onDone: () => void; initial?: string }) {
  const [url, setUrl] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await callPopup("setServer", { url });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  return (
    <form className="pop-auth" onSubmit={submit}>
      <AuthHead title="Connect to your server" sub="PassAuth keeps your vault on a server you run." />
      <label className="field">
        <span>Server address</span>
        <input
          className="input"
          inputMode="url"
          autoCapitalize="off"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://vault.example.com"
          spellCheck={false}
          autoFocus
          required
        />
      </label>
      <ErrorText error={error} />
      <SheetActions>
        <button type="submit" className="btn btn-primary btn-block" disabled={busy || !url}>
          {busy ? "Connecting…" : "Connect"}
        </button>
      </SheetActions>
    </form>
  );
}

// ------------------------------------------------------------------ login

function Login({ state, onDone }: { state: PopupState; onDone: (note?: string) => void }) {
  const [changingServer, setChangingServer] = useState(false);
  // PassAuth's own window opened for "Sign in with another device" starts there, for the email it was opened with.
  const [device, setDevice] = useState<string | null>(() => deviceSignInEmail() || null);
  const [email, setEmail] = useState(device ?? state.email);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [needKey, setNeedKey] = useState(false);
  const [challenge, setChallenge] = useState<TwoFactorChallenge | null>(null);
  const [provider, setProvider] = useState("totp");
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  /** The server's key page is open in PassAuth's security-key window (background/two-step-key.ts). */
  const [waitingKey, setWaitingKey] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await callPopup("login", { email, password, secretKey: secretKey || undefined });
      if ("twoFactor" in r) showChallenge(r.twoFactor);
      else onDone();
    } catch (err) {
      if (codeOf(err) === SECRET_KEY_REQUIRED) setNeedKey(true);
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  }

  /**
   * The server's two-step methods. A security key works through the server's key page where the server offers it
   * (`keyPage`); otherwise only the other methods, with a note when a security key is all the account has.
   */
  function showChallenge(c: TwoFactorChallenge, preferred?: string) {
    const providers = c.providers.filter((p) => p === "totp" || p === "email" || p === "recovery" || (p === "passkey" && c.keyPage === true));
    setChallenge({ ...c, providers });
    setProvider(preferred && providers.includes(preferred) ? preferred : (providers[0] ?? "recovery"));
    setNote(
      c.providers.includes("passkey") && providers.every((p) => p === "recovery")
        ? "This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault."
        : null,
    );
  }

  // A security-key sign-in started before this popup closed (the key window took the focus): waiting, or how it ended.
  // biome-ignore lint/correctness/useExhaustiveDependencies: once, when the sign-in screen opens
  useEffect(() => {
    void callPopup("twoStepKey:status").then(
      (s) => {
        if (!s) return;
        if (s.email) setEmail(s.email);
        if (s.challenge) showChallenge(s.challenge, "passkey");
        setWaitingKey(s.status === "waiting");
        if (s.error) setError(s.error);
      },
      () => {},
    );
  }, []);

  // While the key window is open: the background finishes the sign-in; this follows how it went.
  // biome-ignore lint/correctness/useExhaustiveDependencies: follows `waitingKey` only (showChallenge and onDone are the same each time)
  useEffect(() => {
    if (!waitingKey) return;
    const timer = setInterval(() => {
      void callPopup("twoStepKey:status").then(
        (s) => {
          if (s?.status === "waiting") return;
          setWaitingKey(false);
          // Signed in (or nothing left to wait for): the popup shows what is there now.
          if (!s) return onDone();
          if (s.challenge) showChallenge(s.challenge, "passkey");
          if (s.error) setError(s.error);
        },
        () => {},
      );
    }, 1000);
    return () => clearInterval(timer);
  }, [waitingKey]);

  async function verify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (provider === "passkey") {
        await callPopup("twoStepKey:start", { email, challenge: challenge!, remember });
        setWaitingKey(true);
        setBusy(false);
        return;
      }
      await callPopup("verify2fa", { token: challenge!.token, provider, code, remember });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }

  /**
   * "Sign in with another device": its request lives in the page that made it, and the toolbar popup closes as soon as
   * the browser loses focus (the user goes to their other device), so it runs in PassAuth's own window.
   */
  async function withDevice() {
    setError(null);
    const address = email.trim();
    if (!address) return setError("Enter your email address first.");
    if (new URLSearchParams(location.search).has("popout")) return setDevice(address);
    const browser = await chrome.windows.getCurrent().catch(() => null);
    await openCentered(deviceSignInUrl(address), POPUP_WINDOW, { windowId: browser?.id });
    window.close();
  }

  if (device) {
    return (
      <DeviceSignIn
        email={device}
        onDone={(who) => onDone(`Signed in as ${who}.`)}
        onBack={() => {
          setDevice(null);
          setError(null);
        }}
      />
    );
  }

  if (changingServer) {
    // The status stays "logged-out" after a server change, so this screen isn't remounted: leave the form here.
    const changed = () => {
      setChangingServer(false);
      onDone();
    };
    return <Setup initial={state.server} onDone={changed} />;
  }
  if (challenge && waitingKey) {
    return (
      <div className="pop-auth">
        <AuthHead title="Two-step login" sub={email} />
        <p className="card-text" role="status">
          Waiting for your security key…
        </p>
        <p className="card-text">{KEY_PAGE_WARNING}</p>
        <SheetActions>
          <button
            type="button"
            className="btn btn-ghost btn-block"
            onClick={() =>
              void callPopup("twoStepKey:cancel").then(
                () => setWaitingKey(false),
                (e) => setError(msg(e)),
              )
            }
          >
            Cancel
          </button>
        </SheetActions>
      </div>
    );
  }
  if (challenge) {
    const usingKey = provider === "passkey";
    return (
      <form className="pop-auth" onSubmit={verify}>
        <AuthHead title="Two-step login" sub={email} />
        {challenge.providers.length > 1 && (
          <Choices
            compact
            label="Verify with"
            value={provider}
            onChange={setProvider}
            options={challenge.providers.map((p) => ({
              id: p,
              title: PROVIDER_TITLES[p] ?? p,
              icon: (
                <Tile>
                  <Icon name={PROVIDER_ICONS[p] ?? "key"} />
                </Tile>
              ),
            }))}
          />
        )}
        {usingKey ? (
          <p className="card-text">{KEY_PAGE_TEXT}</p>
        ) : (
          <label className="field">
            <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
            <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
          </label>
        )}
        {note && (
          <div className="alert alert-info" role="status">
            {note}
          </div>
        )}
        <label className="check small">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          <span>Remember this browser for 30 days</span>
        </label>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            provider === "email" && (
              <button
                type="button"
                className="btn btn-text"
                onClick={() =>
                  callPopup("email2fa", { token: challenge.token }).then(
                    () => setNote(`Code sent to ${email}.`),
                    (e) => setError(msg(e)),
                  )
                }
              >
                Email me a code
              </button>
            )
          }
        >
          {usingKey ? (
            <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
              {busy ? "Opening…" : "Use security key"}
            </button>
          ) : (
            <button type="submit" className="btn btn-primary btn-block" disabled={busy || !code}>
              {busy ? "Verifying…" : "Verify and sign in"}
            </button>
          )}
        </SheetActions>
      </form>
    );
  }

  return (
    <form className="pop-auth" onSubmit={submit}>
      <AuthHead title="Sign in to PassAuth" sub={new URL(state.server).host} />
      <label className="field">
        <span>Email</span>
        <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus={!email} />
      </label>
      <label className="field">
        <span>Master password</span>
        <PasswordInput value={password} onChange={setPassword} autoFocus={!!email} />
      </label>
      {needKey && (
        <label className="field">
          <span>Secret Key</span>
          <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="PA1-XXXXXX-…" spellCheck={false} required />
        </label>
      )}
      <ErrorText error={error} />
      <SheetActions
        quiet={
          <>
            {state.deviceSignIn && (
              <button type="button" className="btn btn-text" onClick={() => void withDevice()}>
                Sign in with another device
              </button>
            )}
            <button type="button" className="btn btn-text" onClick={() => setChangingServer(true)}>
              Change server
            </button>
          </>
        }
      >
        <button type="submit" className="btn btn-primary btn-block" disabled={busy || !email || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </SheetActions>
    </form>
  );
}

/** Unlock with the PIN (first, when one is set for this browser session) or the master password. */
function Unlock({ state, onDone }: { state: PopupState; onDone: (note?: string) => void }) {
  // The PIN copy can go while this screen is open (the last wrong try): then only the master password is offered.
  const [pinAvailable, setPinAvailable] = useState(!!state.pinUnlock);
  const [withPin, setWithPin] = useState(pinAvailable);
  const [pin, setPin] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const needKey = state.secretKeyRequired && !state.secretKeyStored;

  /** Unlocked: finish a fill that waited for it (right-click menu, shortcut); then the popup closes, its job done. */
  async function finish() {
    try {
      const r = await callPopup("afterUnlock");
      if (r.filled) return window.close();
      onDone();
    } catch (e) {
      onDone(msg(e));
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await callPopup("unlock", { password, secretKey: secretKey || undefined });
      await finish();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }

  async function submitPin(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await callPopup("pin:unlock", { pin });
      if (r.unlocked) return void (await finish());
      setPin("");
      if (r.triesLeft > 0) setError(`Wrong PIN. ${r.triesLeft} ${r.triesLeft === 1 ? "try" : "tries"} left.`);
      else {
        setPinAvailable(false);
        setWithPin(false);
        setError("Too many wrong PINs, so PIN unlock is off. Unlock with your master password.");
      }
    } catch (err) {
      if (codeOf(err) === "pin_unavailable") {
        setPinAvailable(false);
        setWithPin(false);
        setError("PIN unlock is off. Unlock with your master password.");
      } else setError(msg(err));
    }
    setBusy(false);
  }

  const quiet = (
    <>
      {pinAvailable && (
        <button
          type="button"
          className="btn btn-text"
          onClick={() => {
            setWithPin(!withPin);
            setError(null);
          }}
        >
          {withPin ? "Use master password" : "Use PIN"}
        </button>
      )}
      <button type="button" className="btn btn-text" onClick={() => setSigningOut(true)}>
        Sign out…
      </button>
    </>
  );

  return (
    <>
      {withPin ? (
        <form className="pop-auth" onSubmit={submitPin}>
          <AuthHead title="Unlock PassAuth" sub={state.email} />
          <label className="field">
            <span>PIN</span>
            <input
              className="input mono pin-input"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              maxLength={64}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D+/g, ""))}
              aria-describedby="pin-help"
              autoFocus
            />
            <span id="pin-help" className="field-hint">
              The PIN you set for this browser session.
            </span>
          </label>
          <ErrorText error={error} />
          <SheetActions quiet={quiet}>
            <button type="submit" className="btn btn-primary btn-block" disabled={busy || pin.length < 6}>
              {busy ? "Unlocking…" : "Unlock with PIN"}
            </button>
          </SheetActions>
        </form>
      ) : (
        <form className="pop-auth" onSubmit={submit}>
          <AuthHead title="Unlock PassAuth" sub={state.email} />
          <label className="field">
            <span>Master password</span>
            <PasswordInput value={password} onChange={setPassword} autoFocus />
          </label>
          {needKey && (
            <label className="field">
              <span>Secret Key</span>
              <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} spellCheck={false} required />
            </label>
          )}
          <ErrorText error={error} />
          <SheetActions quiet={quiet}>
            <button type="submit" className="btn btn-primary btn-block" disabled={busy || !password}>
              {busy ? "Unlocking…" : "Unlock"}
            </button>
          </SheetActions>
        </form>
      )}
      {signingOut && <SignOutDialog state={state} onClose={() => setSigningOut(false)} onDone={() => onDone()} />}
    </>
  );
}

// ------------------------------------------------------------------- main

/** The unlocked popup: first where it should start (a page the background asked for, or where it was), then the screens. */
function Main({ state, onChange, startNote }: { state: PopupState; onChange: () => void; startNote?: string | undefined }) {
  const [start, setStart] = useState<Start | null>(null);
  useEffect(() => {
    takeStart(state.activeId).then(setStart, () => setStart({ route: LIST, filter: NO_FILTER, scroll: 0 }));
  }, [state.activeId]);
  if (!start) return <div className="pop" />;
  return <Screens state={state} onChange={onChange} start={start} startNote={startNote} />;
}

function Screens({ state, onChange, start, startNote }: { state: PopupState; onChange: () => void; start: Start; startNote?: string | undefined }) {
  const [route, setRoute] = useState<Route>(start.route);
  // Bumped on every navigation so pages remount and load fresh data (the list stays mounted and reloads its data).
  const [visit, setVisit] = useState(0);
  const [listVersion, setListVersion] = useState(0);
  const [filter, setFilter] = useState<ListFilter>(start.filter);
  const scroll = useRef(start.scroll);
  const [note, setNote] = useState(startNote ?? "");
  const [signingOut, setSigningOut] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  /** One live region for every note (it stays in the page, so each new text is announced). */
  const notify = useCallback((text: string) => {
    // The same text again still changes the region (a zero-width space), so it is read again.
    setNote((old) => (old === text ? `${text}\u200b` : text));
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setNote(""), 4000);
  }, []);
  useEffect(() => {
    if (!startNote) return;
    timer.current = setTimeout(() => setNote(""), 6000);
  }, [startNote]);
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(
    async (req: CopyRequest, label: string) => {
      try {
        await ("text" in req ? callPopup("copy", { text: req.text }) : callPopup("copyField", req));
        notify(copiedNote(label, state.settings.clearClipboard));
        return true;
      } catch (e) {
        notify(msg(e));
        return false;
      }
    },
    [notify, state.settings.clearClipboard],
  );
  const go = useCallback((r: Route) => {
    setRoute(r);
    setVisit((v) => v + 1);
    if (r.tab === "vault" && r.page === "list") setListVersion((v) => v + 1);
  }, []);
  const signOut = useCallback(() => setSigningOut(true), []);
  // Sign-ins on other devices waiting for this account's approval: the newest one's sheet opens over any page.
  const signIns = useSignIns(state.activeId, notify);
  const putOffSignIns = useMemo(() => ({ putOff: signIns.putOff, review: signIns.review }), [signIns.putOff, signIns.review]);
  const ctx = useMemo<Ctx>(() => ({ state, copy, notify, go, reload: onChange, signOut, signIns: putOffSignIns }), [state, copy, notify, go, onChange, signOut, putOffSignIns]);

  // The vault changed while the popup is open (live sync, another device, a save from the page): the list loads its
  // rows again, keeping those on screen until they arrive. Open items and editors stay as they are.
  useEffect(() => {
    let soon: ReturnType<typeof setTimeout> | undefined;
    const onChanged = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      if (!vaultChanged(changes, area, state.activeId)) return;
      clearTimeout(soon);
      soon = setTimeout(() => setListVersion((v) => v + 1), 150);
    };
    chrome.storage.onChanged.addListener(onChanged);
    return () => {
      clearTimeout(soon);
      chrome.storage.onChanged.removeListener(onChanged);
    };
  }, [state.activeId]);

  // Where the popup is, for reopening it within a couple of minutes (dropped on lock and sign-out).
  useEffect(() => saveView({ account: state.activeId, route, filter, scroll: scroll.current }), [state.activeId, route, filter]);
  useEffect(() => {
    addEventListener("pagehide", flushView);
    return () => {
      removeEventListener("pagehide", flushView);
      // Leaving the unlocked screens (locked, signed out): nothing more is written.
      dropPendingView();
    };
  }, []);

  const onList = route.tab === "vault" && route.page === "list";
  // Item pages have their own footer; the tab bar shows everywhere else.
  const inItem = route.tab === "vault" && route.page !== "list";
  return (
    <div className={state.settings.density === "compact" ? "pop compact" : "pop"}>
      <div className="pg-frame" hidden={!onList}>
        <VaultList
          ctx={ctx}
          visible={onList}
          version={listVersion}
          filter={filter}
          setFilter={setFilter}
          scroll={start.scroll}
          onScroll={(top) => {
            scroll.current = top;
            saveView({ account: state.activeId, route, filter, scroll: top });
          }}
        />
      </div>
      {route.tab === "vault" && route.page === "item" && <ItemPage key={visit} id={route.id} ctx={ctx} />}
      {route.tab === "vault" && route.page === "history" && <HistoryPage key={visit} id={route.id} ctx={ctx} />}
      {/* The first page shown may bring back the draft its editor had when the popup closed. */}
      {route.tab === "vault" && route.page === "edit" && <EditPage key={visit} id={route.id} draft={visit === 0 ? start.draft : undefined} ctx={ctx} />}
      {route.tab === "vault" && route.page === "new" && <EditPage key={visit} kind={route.kind} prefill={route.prefill} draft={visit === 0 ? start.draft : undefined} ctx={ctx} />}
      {route.tab === "vault" && route.page === "addSite" && <AddSitePage key={visit} url={route.url} ctx={ctx} />}
      {route.tab === "generator" && <GeneratorPage key={visit} ctx={ctx} />}
      {route.tab === "settings" && <SettingsPage key={visit} ctx={ctx} section={route.section} />}
      <div className="pop-note" role="status" aria-live="polite" aria-atomic="true">
        {note}
      </div>
      {!inItem && (
        <nav className="tabbar" aria-label="Sections">
          {(
            [
              ["vault", "Vault", "vault"],
              ["generator", "Generator", "dice"],
              ["settings", "Settings", "settings"],
            ] as const
          ).map(([t, label, icon]) => (
            <button type="button" key={t} aria-current={route.tab === t ? "page" : undefined} onClick={() => go(t === "vault" ? LIST : { tab: t })}>
              <span className="ic">
                <Icon name={icon} />
              </span>
              {label}
            </button>
          ))}
        </nav>
      )}
      {signingOut && <SignOutDialog state={state} onClose={() => setSigningOut(false)} onDone={onChange} />}
      {!signingOut && signIns.notice?.kind === "code" && <CodeNote code={signIns.notice.code} onDone={signIns.dismiss} />}
      {!signingOut && signIns.notice && signIns.notice.kind !== "code" && <ClosedNote notice={signIns.notice} onDone={signIns.dismiss} />}
      {!signingOut && !signIns.notice && signIns.shown && (
        // Keyed by the request as frozen: another key is another sheet (it never changes in place). Not by the challenge,
        // which the server seals again (other text, same plaintext) at every listing.
        <SignInSheet key={`${signIns.shown.id}\n${signIns.shown.publicKey}`} ctx={ctx} request={signIns.shown} signIns={signIns} />
      )}
    </div>
  );
}
