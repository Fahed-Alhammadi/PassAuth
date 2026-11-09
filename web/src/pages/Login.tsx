import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import { LogoMark } from "../components/Logo";
import { ErrorText, PasswordField } from "../components/ui";
import { errorMessage, friendlyError, usePublicConfig } from "../lib/api";
import { getDesktop } from "../lib/platform";
import { server } from "../lib/server";
import { lastEmail, login, rememberedSecretKey, sendTwoFactorEmail, useVault, verifyTwoFactor, verifyTwoFactorPasskey, WRONG_CREDENTIALS } from "../lib/vault";
import { webauthnSupported } from "../lib/webauthn";

const PROVIDER_LABEL: Record<string, string> = {
  totp: "Authenticator app",
  email: "Email code",
  passkey: "Security key or passkey",
  recovery: "Recovery code",
};

/** Methods this page can offer: security keys only where the browser can run WebAuthn (not in the desktop app's WebView). */
function usableProviders(providers: string[]) {
  const here = (p: string) => p !== "passkey" || (!getDesktop() && webauthnSupported());
  return providers.filter((p) => p in PROVIDER_LABEL && here(p));
}

export function LoginPage() {
  const config = usePublicConfig();
  const { status } = useVault();
  const nav = useNavigate();
  // Go back to the page that sent us here (e.g. a link to /settings/two-step), only within the app.
  const from = (useLocation().state as { from?: string } | null)?.from;
  const next = from && from.startsWith("/") && !from.startsWith("//") && from !== "/login" ? from : "/vault";
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
  const desktop = getDesktop();

  if (status === "unlocked") return <Navigate to={next} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const typed = secretKey.trim();
    const remembered = typed ? null : rememberedSecretKey(email);
    try {
      const r = await login(email, password, typed || remembered);
      if (r.done) nav(next, { replace: true });
      else {
        const usable = usableProviders(r.providers);
        setTwoFactor({ token: r.twoFactorToken, providers: usable });
        setProvider(usable[0] ?? "recovery");
        setNotice(
          r.providers.includes("passkey") && !usable.includes("passkey") && usable.every((p) => p === "recovery")
            ? "This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault in a browser."
            : null,
        );
      }
    } catch (err) {
      const msg = errorMessage(err);
      if (msg === "secret_key_required") {
        setNeedSecretKey(true);
        setError("This account uses a Secret Key. Enter it from your Emergency Kit.");
      } else if (msg === "email_not_verified") {
        setError("Confirm your email address first. Check your inbox for the verification link.");
      } else if (msg === WRONG_CREDENTIALS && remembered) {
        // The Secret Key saved in this browser may be an old one (it changes with the master password).
        setNeedSecretKey(true);
        setError("Wrong master password or Secret Key. If your Secret Key changed on another device, enter the new one from your Emergency Kit.");
      } else setError(friendlyError(err));
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
      nav(next, { replace: true });
    } catch (err) {
      setError(friendlyError(err));
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
      setError(friendlyError(err));
    }
  }

  async function securityKey() {
    if (!twoFactor) return;
    setBusy(true);
    setError(null);
    try {
      await verifyTwoFactorPasskey(twoFactor.token, remember);
      nav(next, { replace: true });
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  const usePasskey = provider === "passkey";

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
              <input className="input" type="email" name="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus={!email} />
            </label>
            <PasswordField label="Master password" value={password} onChange={setPassword} autoFocus={!!email} />
            {needSecretKey && (
              <label className="field">
                <span>Secret Key</span>
                <input
                  className="input mono"
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                  placeholder="PA1-XXXXXX-…"
                  spellCheck={false}
                  autoComplete="off"
                  autoCapitalize="characters"
                  required
                />
              </label>
            )}
            <ErrorText error={error} />
            <button className="btn btn-accent btn-block" disabled={busy || !email || !password}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>
        ) : (
          <form className="auth-panel stack" onSubmit={submitCode}>
            {twoFactor.providers.length > 1 && (
              <label className="field">
                <span>Verify with</span>
                <select className="select" value={provider} onChange={(e) => (setProvider(e.target.value), setCode(""), setError(null))}>
                  {twoFactor.providers.map((p) => (
                    <option key={p} value={p}>
                      {PROVIDER_LABEL[p] ?? p}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {usePasskey ? (
              <p className="card-text">Confirm with your security key or passkey. Insert or tap your key, or use the fingerprint, face or PIN prompt on this device.</p>
            ) : (
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
            )}
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
            {usePasskey ? (
              <button type="button" className="btn btn-accent btn-block" disabled={busy} onClick={securityKey} autoFocus>
                {busy ? "Waiting for your security key…" : "Use security key or passkey"}
              </button>
            ) : (
              <button className="btn btn-accent btn-block" disabled={busy || !code}>
                {busy ? "Verifying…" : "Verify and sign in"}
              </button>
            )}
            <button type="button" className="btn btn-ghost" onClick={() => (setTwoFactor(null), setCode(""), setError(null), setNotice(null))}>
              Use a different account
            </button>
          </form>
        )}

        {config?.signups_allowed !== false && (
          <p className="auth-foot">
            New to this server? <Link to="/register">Create an account</Link>
          </p>
        )}
        {desktop && (
          <p className="auth-foot">
            Connected to <span className="mono">{server.host()}</span>.{" "}
            <button type="button" className="link" onClick={() => desktop.changeServer()}>
              Change server
            </button>
          </p>
        )}
      </div>
    </main>
  );
}
