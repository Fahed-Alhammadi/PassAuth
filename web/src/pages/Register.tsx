import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { LogoMark } from "../components/Logo";
import { KitActions } from "../components/KitActions";
import { CopyButton, ErrorText, Icon, PasswordField, SheetActions, StrengthMeter, WEAK_BITS } from "../components/ui";
import { friendlyError, usePublicConfig } from "../lib/api";
import { estimateBits, login, register } from "../lib/vault";

export function RegisterPage() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  // Invitation links carry ?email=; the server accepts invited addresses even when sign-ups are closed.
  const closed = usePublicConfig()?.signups_allowed === false && !params.get("email");
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
  const [kitSaved, setKitSaved] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 10) return setError("Use at least 10 characters for your master password.");
    if (password !== confirm) return setError("The two passwords don't match.");
    if (estimateBits(password) < WEAK_BITS && !hint) {
      setHint(true);
      return setError("This password is easy to guess. Choose a longer one, or select Create account again to use it anyway.");
    }
    setBusy(true);
    try {
      const r = await register(email, name, password, withSecretKey);
      setDone({ secretKey: r.secretKey, verify: r.emailVerificationRequired });
    } catch (err) {
      setError(friendlyError(err));
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
      setError(friendlyError(err));
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
            <p className="muted">{email}</p>
          </div>
          <div className="auth-panel stack">
            <div className="sheet-context">
              <span className="tile" aria-hidden="true">
                <Icon name={done.secretKey ? "key" : "shield"} size={20} />
              </span>
              <div className="grow">
                <h2 className="sheet-title">{done.secretKey ? "Save your Secret Key" : "Save your Emergency Kit"}</h2>
                <p className="sheet-sub">{done.secretKey ? "Shown only once. PassAuth can't recover it." : "What you need to sign in on a new device"}</p>
              </div>
            </div>
            {done.secretKey ? (
              <>
                <p className="card-text">You need this key, together with your master password, to sign in on a new device.</p>
                <div className="secret-box">
                  <div className="secret-key grow" aria-label="Secret Key">
                    {done.secretKey}
                  </div>
                  <CopyButton value={done.secretKey} label="Copy Secret Key" />
                </div>
              </>
            ) : (
              <p className="card-text">
                The kit records this server's address and your email. Add your master password to it by hand if you keep it somewhere safe.
              </p>
            )}
            <KitActions email={email} secretKey={done.secretKey} onSaved={() => setKitSaved(true)} />
            {done.secretKey && (
              <label className="check">
                <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                <span>I saved my Secret Key somewhere safe</span>
              </label>
            )}
            {done.verify && (
              <div className="alert alert-ok" role="status">
                We sent a verification link to {email}. Open it, then sign in.
              </div>
            )}
            <ErrorText error={error} />
            <SheetActions>
              <button className="btn btn-accent btn-block" disabled={busy || (!!done.secretKey && !saved)} onClick={continueToVault}>
                {done.verify ? "Go to sign in" : busy ? "Opening vault…" : "Open my vault"}
              </button>
            </SheetActions>
            {!done.secretKey && !kitSaved && <p className="small muted">You can also save the kit later in Settings, then Security.</p>}
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
          <h1>Create your account</h1>
          <p className="muted">Everything is encrypted on this device before it reaches the server.</p>
        </div>
        {closed && (
          <div className="alert alert-info" role="note">
            Sign-ups are closed on this server. Ask the administrator for an invitation, then open the link in the invitation email.
          </div>
        )}
        <form className="auth-panel stack" onSubmit={submit}>
          <label className="field">
            <span>Email</span>
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus />
          </label>
          <label className="field">
            <span>Your name</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
          </label>
          <PasswordField
            label="Master password"
            value={password}
            onChange={(v) => (setPassword(v), setHint(false))}
            autoComplete="new-password"
            hint={
              <>
                <StrengthMeter password={password} />
                <span className="field-hint">At least 10 characters. Four or more unrelated words are easy to remember and hard to guess.</span>
              </>
            }
          />
          <PasswordField label="Confirm master password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          <div className="alert alert-warn small" role="note">
            Your master password can't be reset. If you forget it, nobody can recover the data in your vault, not even the server administrator.
          </div>
          <label className="check">
            <input type="checkbox" checked={withSecretKey} onChange={(e) => setWithSecretKey(e.target.checked)} />
            <span>
              Add a Secret Key
              <span className="field-hint block">
                A second, random key that never leaves your devices. Even if the server is breached, your vault can't be cracked by guessing your password.
                You'll enter it once on each new device.
              </span>
            </span>
          </label>
          <ErrorText error={error} />
          <SheetActions
            quiet={
              <Link className="btn btn-text" to="/login">
                Sign in to an existing account
              </Link>
            }
          >
            <button className="btn btn-accent btn-block" disabled={busy}>
              {busy ? "Creating account…" : "Create account"}
            </button>
          </SheetActions>
        </form>
      </div>
    </main>
  );
}
