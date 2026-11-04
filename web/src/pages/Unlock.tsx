import { useState, type FormEvent } from "react";
import { LogoMark } from "../components/Logo";
import { ErrorText, PasswordField } from "../components/ui";
import { friendlyError } from "../lib/api";
import { getBundle, logout, rememberedSecretKey, unlock, useVault } from "../lib/vault";

export function UnlockPage() {
  const { email } = useVault();
  const needsKey = !!getBundle()?.secret_key_enabled;
  const stored = rememberedSecretKey(email);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  // Shown when no key is saved, or when the saved one may be out of date (it changes with the master password).
  const [askKey, setAskKey] = useState(needsKey && !stored);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const typed = secretKey.trim();
    try {
      await unlock(password, needsKey ? typed || stored : null);
    } catch (err) {
      if (needsKey && stored && !typed && !askKey) {
        setAskKey(true);
        setError("Wrong master password or Secret Key. If your Secret Key changed on another device, enter the new one from your Emergency Kit.");
      } else setError(friendlyError(err));
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
          <PasswordField label="Master password" value={password} onChange={setPassword} autoFocus />
          {askKey && (
            <label className="field">
              <span>Secret Key{stored ? " (leave empty to use the one saved in this browser)" : ""}</span>
              <input
                className="input mono"
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
                placeholder="PA1-XXXXXX-…"
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="characters"
                required={!stored}
              />
            </label>
          )}
          <ErrorText error={error} />
          <button className="btn btn-accent btn-block" disabled={busy || !password}>
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
