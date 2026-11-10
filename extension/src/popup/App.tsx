import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { LogoMark } from "@web/components/Logo";
import { ErrorText, Icon, PasswordInput, SheetActions } from "@web/components/ui";
import { send, type PopupState, type TwoFactorChallenge } from "../shared/messages";
import { msg, seconds, type CopyRequest, type Ctx, type Route } from "./ctx";
import { GeneratorPage } from "./generator";
import { SettingsPage } from "./settings";
import { Choices, Tile } from "./sheet";
import { OtherAccounts } from "./shell";
import { EditPage, ItemPage, VaultList, type ListFilter } from "./vault";

/** Copies through the background, which also clears the clipboard after the user's delay (even once the popup closes). */
const copiedNote = (label: string, clearAfter: number) => `${label} copied.${clearAfter ? ` Clipboard clears in ${seconds(clearAfter)}.` : ""}`;

export function App() {
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => send<PopupState>({ type: "state" }).then(setState, (e) => setError(msg(e))), []);
  useEffect(() => void reload(), [reload]);

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
  if (state.status === "logged-out") return screen(<Login state={state} onDone={reload} />);
  if (state.status === "locked") return screen(<Unlock state={state} onDone={reload} />);
  return <Main key={state.activeId} state={state} onChange={reload} />;
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
      await send({ type: "setServer", url });
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
        <input className="input" inputMode="url" autoCapitalize="off" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://vault.example.com" spellCheck={false} autoFocus required />
      </label>
      <ErrorText error={error} />
      <SheetActions>
        <button className="btn btn-primary btn-block" disabled={busy || !url}>
          {busy ? "Connecting…" : "Connect"}
        </button>
      </SheetActions>
    </form>
  );
}

// ------------------------------------------------------------------ login

function Login({ state, onDone }: { state: PopupState; onDone: () => void }) {
  const [changingServer, setChangingServer] = useState(false);
  const [email, setEmail] = useState(state.email);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [needKey, setNeedKey] = useState(false);
  const [challenge, setChallenge] = useState<TwoFactorChallenge | null>(null);
  const [provider, setProvider] = useState("totp");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await send<{ done?: true; twoFactor?: TwoFactorChallenge }>({ type: "login", email, password, secretKey: secretKey || undefined });
      if (r.twoFactor) {
        // Security keys (WebAuthn) can't be used from the popup yet: offer the other methods.
        const providers = r.twoFactor.providers.filter((p) => p === "totp" || p === "email" || p === "recovery");
        setChallenge({ ...r.twoFactor, providers });
        setProvider(providers[0] ?? "recovery");
        setNote(
          r.twoFactor.providers.includes("passkey") && providers.every((p) => p === "recovery")
            ? "This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault."
            : null,
        );
      } else onDone();
    } catch (err) {
      if (err instanceof Error && err.message === "secret_key_required") setNeedKey(true);
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: "verify2fa", token: challenge!.token, provider, code, remember: true });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }

  if (changingServer) {
    // The status stays "logged-out" after a server change, so this screen isn't remounted: leave the form here.
    const changed = () => {
      setChangingServer(false);
      onDone();
    };
    return <Setup initial={state.server} onDone={changed} />;
  }
  if (challenge) {
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
              title: p === "totp" ? "Authenticator app" : p === "email" ? "Email code" : "Recovery code",
              icon: (
                <Tile>
                  <Icon name={p === "totp" ? "phone" : p === "email" ? "mail" : "key"} />
                </Tile>
              ),
            }))}
          />
        )}
        <label className="field">
          <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
          <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
        </label>
        {note && (
          <div className="alert alert-info" role="status">
            {note}
          </div>
        )}
        <ErrorText error={error} />
        <SheetActions
          quiet={
            provider === "email" && (
              <button
                type="button"
                className="btn btn-text"
                onClick={() => send({ type: "email2fa", token: challenge.token }).then(() => setNote(`Code sent to ${email}.`), (e) => setError(msg(e)))}
              >
                Email me a code
              </button>
            )
          }
        >
          <button className="btn btn-primary btn-block" disabled={busy || !code}>
            {busy ? "Verifying…" : "Verify and sign in"}
          </button>
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
          <button type="button" className="btn btn-text" onClick={() => setChangingServer(true)}>
            Change server
          </button>
        }
      >
        <button className="btn btn-primary btn-block" disabled={busy || !email || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </SheetActions>
    </form>
  );
}

function Unlock({ state, onDone }: { state: PopupState; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const needKey = state.secretKeyRequired && !state.secretKeyStored;
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: "unlock", password, secretKey: secretKey || undefined });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  return (
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
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={() => send({ type: "logout" }).then(onDone)}>
            Sign out
          </button>
        }
      >
        <button className="btn btn-primary btn-block" disabled={busy || !password}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </SheetActions>
    </form>
  );
}

// ------------------------------------------------------------------- main

function Main({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const [route, setRoute] = useState<Route>({ tab: "vault", page: "list" });
  // Bumped on every navigation so pages remount and load fresh data.
  const [visit, setVisit] = useState(0);
  const [filter, setFilter] = useState<ListFilter>({ query: "", kind: "", folder: null });
  const [note, setNote] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const notify = useCallback((text: string) => {
    setNote(text);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setNote(null), 4000);
  }, []);
  const copy = useCallback(
    (req: CopyRequest, label: string) =>
      send("text" in req ? { type: "copy", text: req.text } : { type: "copyField", ...req }).then(
        () => notify(copiedNote(label, state.settings.clearClipboard)),
        (e) => notify(msg(e)),
      ),
    [notify, state.settings.clearClipboard],
  );
  const go = useCallback((r: Route) => (setRoute(r), setVisit((v) => v + 1)), []);
  const ctx = useMemo<Ctx>(() => ({ state, copy, notify, go, reload: onChange }), [state, copy, notify, go, onChange]);

  // Item pages have their own footer; the tab bar shows everywhere else.
  const inItem = route.tab === "vault" && route.page !== "list";
  return (
    <div className="pop">
      {route.tab === "vault" && route.page === "list" && <VaultList key={visit} ctx={ctx} filter={filter} setFilter={setFilter} />}
      {route.tab === "vault" && route.page === "item" && <ItemPage key={visit} id={route.id} ctx={ctx} />}
      {route.tab === "vault" && route.page === "edit" && <EditPage key={visit} id={route.id} ctx={ctx} />}
      {route.tab === "vault" && route.page === "new" && <EditPage key={visit} kind={route.kind} ctx={ctx} />}
      {route.tab === "generator" && <GeneratorPage key={visit} ctx={ctx} />}
      {route.tab === "settings" && <SettingsPage key={visit} ctx={ctx} section={route.section} />}
      {note && (
        <div className="pop-note" role="status">
          {note}
        </div>
      )}
      {!inItem && (
        <nav className="tabbar" aria-label="Sections">
          {(
            [
              ["vault", "Vault", "vault"],
              ["generator", "Generator", "dice"],
              ["settings", "Settings", "settings"],
            ] as const
          ).map(([t, label, icon]) => (
            <button key={t} aria-current={route.tab === t ? "page" : undefined} onClick={() => go(t === "vault" ? { tab: "vault", page: "list" } : { tab: t })}>
              <span className="ic">
                <Icon name={icon} />
              </span>
              {label}
            </button>
          ))}
        </nav>
      )}
    </div>
  );
}
