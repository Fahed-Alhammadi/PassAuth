import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { LogoMark } from "@web/components/Logo";
import { ErrorText, Icon, PasswordInput } from "@web/components/ui";
import { send, type PopupState, type TwoFactorChallenge } from "../shared/messages";
import { msg, seconds, type CopyRequest, type Ctx, type Route } from "./ctx";
import { GeneratorPage } from "./generator";
import { SettingsPage } from "./settings";
import { EditPage, ItemPage, VaultList, type ListFilter } from "./vault";

/** Copies through the background, which also clears the clipboard after the user's delay (even once the popup closes). */
const copiedNote = (label: string, clearAfter: number) => `${label} copied.${clearAfter ? ` Clipboard clears in ${seconds(clearAfter)}.` : ""}`;

export function App() {
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => send<PopupState>({ type: "state" }).then(setState, (e) => setError(msg(e))), []);
  useEffect(() => void reload(), [reload]);

  if (!state) return <div className="pop-auth">{error ? <ErrorText error={error} /> : null}</div>;
  if (state.status === "setup") return <Setup onDone={reload} />;
  if (state.status === "logged-out") return <Login state={state} onDone={reload} />;
  if (state.status === "locked") return <Unlock state={state} onDone={reload} />;
  return <Main state={state} onChange={reload} />;
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
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Connect to your PassAuth server</h1>
      <label className="field">
        <span>Server address</span>
        <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://vault.example.com" autoFocus required />
      </label>
      <ErrorText error={error} />
      <button className="btn btn-accent btn-block" disabled={busy || !url}>
        {busy ? "Checking…" : "Connect"}
      </button>
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
        setChallenge(r.twoFactor);
        setProvider(r.twoFactor.providers[0]);
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

  if (changingServer) return <Setup initial={state.server} onDone={onDone} />;
  if (challenge) {
    return (
      <form className="pop-auth" onSubmit={verify}>
        <h1>Two-step login</h1>
        {challenge.providers.length > 1 && (
          <label className="field">
            <span>Verify with</span>
            <select className="select" value={provider} onChange={(e) => setProvider(e.target.value)}>
              {challenge.providers.map((p) => (
                <option key={p} value={p}>
                  {p === "totp" ? "Authenticator app" : p === "email" ? "Email code" : "Recovery code"}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
          <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
        </label>
        {provider === "email" && (
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => send({ type: "email2fa", token: challenge.token }).then(() => setNote(`Code sent to ${email}.`), (e) => setError(msg(e)))}
          >
            Email me a code
          </button>
        )}
        {note && <div className="alert alert-ok">{note}</div>}
        <ErrorText error={error} />
        <button className="btn btn-accent btn-block" disabled={busy || !code}>
          {busy ? "Verifying…" : "Verify and sign in"}
        </button>
      </form>
    );
  }

  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Sign in to PassAuth</h1>
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
      <button className="btn btn-accent btn-block" disabled={busy || !email || !password}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <p className="small muted" style={{ textAlign: "center" }}>
        {new URL(state.server).host}{" "}
        <button type="button" className="link" onClick={() => setChangingServer(true)}>
          Change server
        </button>
      </p>
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
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Unlock PassAuth</h1>
      <p className="muted small" style={{ textAlign: "center" }}>
        {state.email}
      </p>
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
      <button className="btn btn-accent btn-block" disabled={busy || !password}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <button type="button" className="btn btn-ghost" onClick={() => send({ type: "logout" }).then(onDone)}>
        Sign out
      </button>
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
        <div className={`pop-note${inItem ? " above-foot" : ""}`} role="status">
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
