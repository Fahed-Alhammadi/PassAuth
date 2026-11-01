import { useCallback, useEffect, useState, type FormEvent } from "react";
import { LogoMark, Wordmark } from "@web/components/Logo";
import { ErrorText, Icon, PasswordInput } from "@web/components/ui";
import type { Item } from "@web/lib/types";
import { send, type ItemSummary, type PopupState, type TwoFactorChallenge } from "../shared/messages";

const msg = (e: unknown) => {
  const m = e instanceof Error ? e.message : String(e);
  return m === "secret_key_required" ? "This account uses a Secret Key. Enter it from your Emergency Kit." : m === "email_not_verified" ? "Confirm your email address first, then sign in." : m;
};

async function copy(value: string, setNote: (s: string) => void, label: string) {
  await navigator.clipboard.writeText(value);
  setNote(`${label} copied. Clipboard clears in 30 seconds.`);
  // The popup may close before then; the background can't touch the clipboard, so best effort here.
  setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30_000);
}

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
      <button className="btn btn-brass btn-block" disabled={busy || !url}>
        {busy ? "Checking…" : "Connect"}
      </button>
    </form>
  );
}

// ------------------------------------------------------------------ login

function Login({ state, onDone }: { state: PopupState; onDone: () => void }) {
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
        <button className="btn btn-brass btn-block" disabled={busy || !code}>
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
      <button className="btn btn-brass btn-block" disabled={busy || !email || !password}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <p className="small muted" style={{ textAlign: "center" }}>
        {new URL(state.server).host}
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
      <button className="btn btn-brass btn-block" disabled={busy || !password}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <button type="button" className="btn btn-ghost" onClick={() => send({ type: "logout" }).then(onDone)}>
        Sign out
      </button>
    </form>
  );
}

// ------------------------------------------------------------------- main

type Tab = "vault" | "generator" | "settings";

function Main({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const [tab, setTab] = useState<Tab>("vault");
  const [openId, setOpenId] = useState<string | null>(null);
  return (
    <>
      <header className="pop-head">
        <Wordmark />
        <span className="grow" />
        <button className="btn btn-icon" title="Open web vault" aria-label="Open web vault" onClick={() => chrome.tabs.create({ url: state.server })}>
          <Icon name="external" />
        </button>
        <button className="btn btn-icon" title="Lock" aria-label="Lock" onClick={() => send({ type: "lock" }).then(onChange)}>
          <Icon name="lock" />
        </button>
      </header>
      <div className="pop-body">
        {tab === "vault" && (openId ? <Detail id={openId} onBack={() => setOpenId(null)} /> : <ItemList onOpen={setOpenId} />)}
        {tab === "generator" && <Generator />}
        {tab === "settings" && <Settings state={state} onChange={onChange} />}
      </div>
      <nav className="pop-tabs" aria-label="Sections">
        {(
          [
            ["vault", "Vault", "vault"],
            ["generator", "Generator", "dice"],
            ["settings", "Settings", "settings"],
          ] as const
        ).map(([t, label, icon]) => (
          <button key={t} aria-current={tab === t} onClick={() => (setTab(t), setOpenId(null))}>
            <Icon name={icon} />
            {label}
          </button>
        ))}
      </nav>
    </>
  );
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function ItemList({ onOpen }: { onOpen: (id: string) => void }) {
  const [data, setData] = useState<{ suggested: ItemSummary[]; all: ItemSummary[] } | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [host, setHost] = useState("");
  useEffect(() => {
    activeTab().then(async (tab) => {
      const url = tab?.url?.startsWith("http") ? tab.url : undefined;
      if (url) setHost(new URL(url).hostname);
      send({ type: "items", url }).then(setData, (e) => setError(msg(e)));
    });
  }, []);

  async function fill(id: string) {
    try {
      const tab = await activeTab();
      if (!tab?.id) return;
      await send({ type: "fill", id, tabId: tab.id });
      window.close();
    } catch (e) {
      setError(msg(e));
    }
  }

  if (!data) return error ? <ErrorText error={error} /> : null;
  const q = query.trim().toLowerCase();
  const filtered = q ? data.all.filter((i) => i.name.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q)) : data.all;
  const row = (i: ItemSummary, canFill: boolean) => (
    <div className="pop-row" key={i.id}>
      <span className="avatar">{(i.name[0] ?? "?").toUpperCase()}</span>
      <button className="main" onClick={() => onOpen(i.id)}>
        <span className="title">{i.name}</span>
        <span className="sub">{i.subtitle}</span>
      </button>
      {canFill && i.hasPassword && (
        <button className="btn btn-primary pop-fill" onClick={() => fill(i.id)}>
          Fill
        </button>
      )}
    </div>
  );

  return (
    <>
      <input className="input" type="search" placeholder="Search vault" aria-label="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
      <ErrorText error={error} />
      {!q && host && (
        <>
          <div className="pop-section">For {host}</div>
          {data.suggested.length ? (
            <div className="pop-list">{data.suggested.map((i) => row(i, true))}</div>
          ) : (
            <p className="small muted">No logins saved for this site yet. Sign in and PassAuth will offer to save it.</p>
          )}
        </>
      )}
      <div className="pop-section">{q ? `Results for "${query}"` : "All items"}</div>
      {filtered.length ? (
        <div className="pop-list">{filtered.slice(0, 200).map((i) => row(i, data.suggested.some((s) => s.id === i.id)))}</div>
      ) : (
        <p className="small muted">{q ? "Nothing matches your search." : "Your vault is empty. Add items in the web vault."}</p>
      )}
    </>
  );
}

function Detail({ id, onBack }: { id: string; onBack: () => void }) {
  const [item, setItem] = useState<Item | null>(null);
  const [code, setCode] = useState<{ code: string; remaining: number } | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [show, setShow] = useState(false);
  useEffect(() => {
    send<{ item: Item }>({ type: "item", id }).then((r) => setItem(r.item));
  }, [id]);
  useEffect(() => {
    if (!item?.login?.totp) return;
    const tick = () => send({ type: "totp", id }).then(setCode, () => {});
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [item, id]);
  if (!item) return null;
  const l = item.login;
  const field = (label: string, value: string, secret = false) =>
    value ? (
      <div className="pop-row">
        <div className="grow">
          <span className="sub">{label}</span>
          <span className={secret ? "mono" : undefined} style={{ display: "block", overflowWrap: "anywhere" }}>
            {secret && !show ? "••••••••••" : value}
          </span>
        </div>
        {secret && (
          <button className="btn btn-icon" aria-label={show ? "Hide" : "Show"} onClick={() => setShow(!show)}>
            <Icon name={show ? "eyeOff" : "eye"} />
          </button>
        )}
        <button className="btn btn-icon" aria-label={`Copy ${label.toLowerCase()}`} onClick={() => copy(value, setNote, label)}>
          <Icon name="copy" />
        </button>
      </div>
    ) : null;
  return (
    <>
      <button className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={onBack}>
        <Icon name="back" /> Back
      </button>
      <h2 style={{ overflowWrap: "anywhere" }}>{item.name}</h2>
      <div className="pop-list">
        {l && field("Username", l.username)}
        {l && field("Password", l.password, true)}
        {code && (
          <div className="pop-row">
            <div className="grow">
              <span className="sub">One-time code, {code.remaining}s left</span>
              <span className="totp-code" style={{ fontSize: "1.3rem" }}>
                {code.code.slice(0, 3)} {code.code.slice(3)}
              </span>
            </div>
            <button className="btn btn-icon" aria-label="Copy code" onClick={() => copy(code.code, setNote, "Code")}>
              <Icon name="copy" />
            </button>
          </div>
        )}
        {l?.urls.filter((u) => u.url).map((u, n) => field(n ? `Website ${n + 1}` : "Website", u.url))}
        {item.card && field("Card number", item.card.number, true)}
        {item.card && field("Security code", item.card.code, true)}
        {item.notes && field("Notes", item.notes)}
      </div>
      {l?.passkeys.length ? <p className="small muted">{l.passkeys.length === 1 ? "Has a passkey" : `Has ${l.passkeys.length} passkeys`} for {l.passkeys[0].rp_id}.</p> : null}
      {note && <div className="alert alert-ok small">{note}</div>}
    </>
  );
}

function Generator() {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [value, setValue] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const gen = useCallback(
    () => send<string>({ type: "generate", mode, options: mode === "password" ? { length } : { words: Math.max(3, Math.round(length / 4)) } }).then(setValue),
    [mode, length],
  );
  useEffect(() => void gen(), [gen]);
  return (
    <>
      <div className="row">
        <button className={`btn grow${mode === "password" ? " btn-primary" : ""}`} onClick={() => setMode("password")}>
          Password
        </button>
        <button className={`btn grow${mode === "passphrase" ? " btn-primary" : ""}`} onClick={() => setMode("passphrase")}>
          Passphrase
        </button>
      </div>
      <div className="gen-out">{value}</div>
      <label className="field">
        <span>{mode === "password" ? `Length: ${length}` : `Words: ${Math.max(3, Math.round(length / 4))}`}</span>
        <input type="range" min={mode === "password" ? 8 : 12} max={mode === "password" ? 64 : 40} value={length} onChange={(e) => setLength(+e.target.value)} />
      </label>
      <div className="row">
        <button className="btn btn-brass grow" onClick={() => copy(value, setNote, mode === "password" ? "Password" : "Passphrase")}>
          Copy
        </button>
        <button className="btn grow" onClick={gen}>
          Regenerate
        </button>
      </div>
      {note && <div className="alert alert-ok small">{note}</div>}
    </>
  );
}

function Settings({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const [minutes, setMinutes] = useState(state.autoLockMinutes);
  const [changingServer, setChangingServer] = useState(false);
  if (changingServer) return <Setup initial={state.server} onDone={onChange} />;
  return (
    <div className="stack">
      <div className="card">
        <div className="small muted">Signed in as</div>
        <div>{state.email}</div>
        <div className="small muted">{state.server}</div>
      </div>
      <label className="field">
        <span>Lock after inactivity</span>
        <select
          className="select"
          value={minutes}
          onChange={(e) => {
            setMinutes(+e.target.value);
            void send({ type: "settings", autoLockMinutes: +e.target.value });
          }}
        >
          {[1, 5, 15, 30, 60, 240].map((m) => (
            <option key={m} value={m}>
              {m < 60 ? `${m} minute${m > 1 ? "s" : ""}` : `${m / 60} hour${m > 60 ? "s" : ""}`}
            </option>
          ))}
          <option value={0}>Only when the browser closes</option>
        </select>
      </label>
      <button className="btn" onClick={() => send({ type: "sync" }).then(onChange)}>
        Sync now
      </button>
      <button className="btn" onClick={() => send({ type: "logout" }).then(() => setChangingServer(true))}>
        Change server
      </button>
      <button className="btn btn-danger" onClick={() => send({ type: "logout" }).then(onChange)}>
        Sign out
      </button>
    </div>
  );
}
