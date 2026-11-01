import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router";
import { LogoMark } from "../components/Logo";
import { ErrorText, PasswordInput } from "../components/ui";
import { errorMessage } from "../lib/api";
import { lastEmail, login, rememberedSecretKey, sendTwoFactorEmail, useVault, verifyTwoFactor } from "../lib/vault";

const PROVIDER_LABEL: Record<string, string> = {
  totp: "Authenticator app",
  email: "Email code",
  recovery: "Recovery code",
};

export function LoginPage() {
  const { status } = useVault();
  const nav = useNavigate();
  const [email, setEmail] = useState(lastEmail());
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [needSecretKey, setNeedSecretKey] = useState(false);
  const [twoFactor, setTwoFactor] = useState<{ token: string; providers: string[] } | null>(null);
  const [provider, setProvider] = useState("totp");
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  if (status === "unlocked") return <Navigate to="/vault" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const sk = secretKey.trim() || rememberedSecretKey(email);
      const r = await login(email, password, sk);
      if (r.done) nav("/vault", { replace: true });
      else {
        setTwoFactor({ token: r.twoFactorToken, providers: r.providers });
        setProvider(r.providers[0]);
      }
    } catch (err) {
      const msg = errorMessage(err);
      if (msg === "secret_key_required") {
        setNeedSecretKey(true);
        setError("This account uses a Secret Key. Enter it from your Emergency Kit.");
      } else if (msg === "email_not_verified") {
        setError("Confirm your email address first. Check your inbox for the verification link.");
      } else setError(msg);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    if (!twoFactor) return;
    setBusy(true);
    setError(null);
    try {
      await verifyTwoFactor(twoFactor.token, provider, code, remember);
      nav("/vault", { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function emailCode() {
    if (!twoFactor) return;
    try {
      await sendTwoFactorEmail(twoFactor.token);
      setNotice(`We sent a code to ${email}.`);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>{twoFactor ? "Two-step login" : "Sign in to PassAuth"}</h1>
        </div>

        {!twoFactor ? (
          <form className="auth-panel stack" onSubmit={submit}>
            <label className="field">
              <span>Email</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus={!email} />
            </label>
            <label className="field">
              <span>Master password</span>
              <PasswordInput value={password} onChange={setPassword} autoFocus={!!email} />
            </label>
            {needSecretKey && (
              <label className="field">
                <span>Secret Key</span>
                <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="PA1-XXXXXX-…" spellCheck={false} autoComplete="off" required />
              </label>
            )}
            <ErrorText error={error} />
            <button className="btn btn-accent btn-block" disabled={busy || !email || !password}>
              {busy ? "Unlocking…" : "Sign in"}
            </button>
          </form>
        ) : (
          <form className="auth-panel stack" onSubmit={submitCode}>
            {twoFactor.providers.length > 1 && (
              <label className="field">
                <span>Verify with</span>
                <select className="select" value={provider} onChange={(e) => (setProvider(e.target.value), setCode(""))}>
                  {twoFactor.providers.map((p) => (
                    <option key={p} value={p}>
                      {PROVIDER_LABEL[p] ?? p}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="field">
              <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
              <input
                className="input mono"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode={provider === "recovery" ? "text" : "numeric"}
                autoComplete="one-time-code"
                autoFocus
                required
              />
            </label>
            {provider === "email" && (
              <button type="button" className="btn btn-ghost" onClick={emailCode}>
                Email me a code
              </button>
            )}
            {notice && <div className="alert alert-ok">{notice}</div>}
            <label className="check small">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
              <span>Don't ask again on this device for 30 days</span>
            </label>
            <ErrorText error={error} />
            <button className="btn btn-accent btn-block" disabled={busy || !code}>
              {busy ? "Verifying…" : "Verify and sign in"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => (setTwoFactor(null), setCode(""), setError(null))}>
              Use a different account
            </button>
          </form>
        )}

        <p className="auth-foot">
          New to this server? <Link to="/register">Create an account</Link>
        </p>
      </div>
    </main>
  );
}
