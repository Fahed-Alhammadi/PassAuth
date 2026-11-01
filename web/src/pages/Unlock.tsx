import { useState, type FormEvent } from "react";
import { LogoMark } from "../components/Logo";
import { ErrorText, PasswordInput } from "../components/ui";
import { errorMessage } from "../lib/api";
import { getBundle, logout, rememberedSecretKey, unlock, useVault } from "../lib/vault";

export function UnlockPage() {
  const { email } = useVault();
  const needsKey = !!getBundle()?.secret_key_enabled;
  const stored = rememberedSecretKey(email);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlock(password, needsKey ? secretKey.trim() || stored : null);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>Your vault is locked</h1>
          <p className="muted">{email}</p>
        </div>
        <form className="auth-panel stack" onSubmit={submit}>
          <label className="field">
            <span>Master password</span>
            <PasswordInput value={password} onChange={setPassword} autoFocus />
          </label>
          {needsKey && !stored && (
            <label className="field">
              <span>Secret Key</span>
              <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="PA1-XXXXXX-…" spellCheck={false} required />
            </label>
          )}
          <ErrorText error={error} />
          <button className="btn btn-brass btn-block" disabled={busy || !password}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
          <button type="button" className="btn btn-ghost" onClick={logout}>
            Sign out
          </button>
        </form>
      </div>
    </main>
  );
}
