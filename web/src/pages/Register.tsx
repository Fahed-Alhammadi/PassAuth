import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { LogoMark } from "../components/Logo";
import { CopyButton, ErrorText, PasswordInput, StrengthMeter } from "../components/ui";
import { errorMessage } from "../lib/api";
import { estimateBits, login, register } from "../lib/vault";

export function downloadEmergencyKit(email: string, secretKey: string) {
  const text = [
    "PassAuth Emergency Kit",
    "",
    `Server:      ${location.origin}`,
    `Email:       ${email}`,
    `Secret Key:  ${secretKey}`,
    "",
    "Master password: ______________________________",
    "",
    "Keep this kit somewhere safe and offline, such as a printed copy in a drawer",
    "or safe. You need the Secret Key and your master password to sign in on a new",
    "device. PassAuth cannot recover either of them for you.",
    "",
  ].join("\n");
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: "PassAuth-Emergency-Kit.txt" });
  a.click();
  URL.revokeObjectURL(url);
}

export function RegisterPage() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [email, setEmail] = useState(params.get("email") ?? "");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [hint, setHint] = useState(false);
  const [withSecretKey, setWithSecretKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ secretKey: string | null; verify: boolean } | null>(null);
  const [saved, setSaved] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 10) return setError("Use at least 10 characters for your master password.");
    if (password !== confirm) return setError("The two passwords don't match.");
    if (estimateBits(password) < 50 && !hint) {
      setHint(true);
      return setError("This password is easy to guess. Choose a longer one, or select Create account again to use it anyway.");
    }
    setBusy(true);
    try {
      const r = await register(email, name, password, withSecretKey);
      setDone({ secretKey: r.secretKey, verify: r.emailVerificationRequired });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function continueToVault() {
    if (done?.verify) return nav("/login");
    setBusy(true);
    try {
      await login(email, password, done?.secretKey ?? null);
      nav("/vault", { replace: true });
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  if (done) {
    return (
      <main className="auth">
        <div className="auth-card">
          <div className="auth-head">
            <LogoMark size={56} />
            <h1>Your vault is ready</h1>
          </div>
          <div className="auth-panel stack">
            {done.secretKey && (
              <>
                <p>
                  This is your Secret Key. You need it, together with your master password, to sign in on a new device. Save it now: it is shown only once and
                  PassAuth cannot recover it.
                </p>
                <div className="secret-key">{done.secretKey}</div>
                <div className="row">
                  <button type="button" className="btn grow" onClick={() => downloadEmergencyKit(email, done.secretKey!)}>
                    Download Emergency Kit
                  </button>
                  <CopyButton value={done.secretKey} label="Copy Secret Key" />
                </div>
                <label className="check">
                  <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                  <span>I saved my Secret Key somewhere safe</span>
                </label>
              </>
            )}
            {done.verify && <div className="alert alert-ok">We sent a verification link to {email}. Open it, then sign in.</div>}
            <ErrorText error={error} />
            <button className="btn btn-brass btn-block" disabled={busy || (!!done.secretKey && !saved)} onClick={continueToVault}>
              {done.verify ? "Go to sign in" : busy ? "Opening vault…" : "Open my vault"}
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>Create your PassAuth account</h1>
          <p className="muted">Everything is encrypted on this device before it reaches the server.</p>
        </div>
        <form className="auth-panel stack" onSubmit={submit}>
          <label className="field">
            <span>Email</span>
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus />
          </label>
          <label className="field">
            <span>Your name</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
          </label>
          <label className="field">
            <span>Master password</span>
            <PasswordInput value={password} onChange={(v) => (setPassword(v), setHint(false))} autoComplete="new-password" />
          </label>
          <StrengthMeter password={password} />
          <label className="field">
            <span>Confirm master password</span>
            <PasswordInput value={confirm} onChange={setConfirm} autoComplete="new-password" />
          </label>
          <div className="alert alert-brass small">
            Your master password can't be reset. If you forget it, the data in your vault can't be recovered by anyone, including the server administrator.
          </div>
          <label className="check">
            <input type="checkbox" checked={withSecretKey} onChange={(e) => setWithSecretKey(e.target.checked)} />
            <span>
              Add a Secret Key
              <span className="small muted" style={{ display: "block" }}>
                A second, random key that never leaves your devices. Even if the server is breached, your vault can't be cracked by guessing your password.
                You'll enter it once on each new device.
              </span>
            </span>
          </label>
          <ErrorText error={error} />
          <button className="btn btn-brass btn-block" disabled={busy}>
            {busy ? "Creating account…" : "Create account"}
          </button>
        </form>
        <p className="auth-foot">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </main>
  );
}
