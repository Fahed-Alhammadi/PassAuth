import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import { LoginPhrase } from "../components/DeviceSignIn";
import { LogoMark } from "../components/Logo";
import { ErrorText, Icon, PasswordField, SheetActions, type IconName } from "../components/ui";
import { SERVER_UPDATE_NEEDED, errorMessage, friendlyError, hasErrorCode, hasFeature, serverTooOld, usePublicConfig } from "../lib/api";
import { CODE_FORMAT, CODE_STOPPED, DEVICE_LOGIN_FEATURE, codeDigits, countdown, wrongCodeText, type DeviceLoginRun, type DeviceLoginState } from "../lib/device-login";
import { startDeviceLogin } from "../lib/device-login-client";
import { KEY_PAGE_FEATURE, KEY_PAGE_MISMATCH, KEY_PAGE_WARNING, keyPageUrl, keyPageWaiter } from "../lib/key-page";
import { getDesktop } from "../lib/platform";
import { afterSignIn } from "../lib/routes";
import { server } from "../lib/server";
import {
  cancelPendingSignIn,
  confirmDeviceLogin,
  finishTwoFactorPasskey,
  getState,
  lastEmail,
  login,
  logout,
  rememberedSecretKey,
  sendTwoFactorEmail,
  startTwoFactorPasskey,
  useVault,
  verifyTwoFactor,
  type TwoStepOutcome,
  verifyTwoFactorPasskey,
  WRONG_CREDENTIALS,
} from "../lib/vault";
import { webauthnSupported } from "../lib/webauthn";

const PROVIDER_LABEL: Record<string, string> = {
  totp: "Authenticator app",
  email: "Email code",
  passkey: "Security key or passkey",
  recovery: "Recovery code",
};
const PROVIDER_ICON: Record<string, IconName> = { totp: "phone", email: "mail", passkey: "key", recovery: "note" };

/**
 * Methods this page can offer: security keys where the browser can run WebAuthn, or (`handOff`) where the app hands the
 * ceremony to the server's key page in the browser (desktop app, servers with `two_step_key_page`). The desktop app's
 * WebView itself can't run WebAuthn for the server.
 */
function usableProviders(providers: string[], handOff: boolean) {
  const here = (p: string) => p !== "passkey" || handOff || (!getDesktop() && webauthnSupported());
  return providers.filter((p) => p in PROVIDER_LABEL && here(p));
}

/** The current time, ticking every `ms` while `ms` is set. */
function useNow(ms: number | null) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (ms === null) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(timer);
  }, [ms]);
  return now;
}

export function LoginPage() {
  const config = usePublicConfig();
  const { status } = useVault();
  const nav = useNavigate();
  // Go back to the page that sent us here (e.g. a link to /settings/two-step), only within the app.
  const next = afterSignIn(useLocation().state);
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
  const [hint, setHint] = useState<string | null>(null);
  /** Signing in with another device's approval: where the request stands (null: the master password form). */
  const [device, setDevice] = useState<DeviceLoginState | null>(null);
  const deviceRun = useRef<DeviceLoginRun | null>(null);
  const deviceTurn = useRef<object | null>(null);
  const emailInput = useRef<HTMLInputElement>(null);
  const desktop = getDesktop();
  // A server too old for this app: nothing is sent to it, and the screen says what to do.
  const outdated = serverTooOld(config);
  const canUseDevice = !outdated && hasFeature(config, DEVICE_LOGIN_FEATURE);
  // Desktop: two-step login with a security key goes through the server's key page in the browser.
  const handOff = !!desktop?.securityKeyHandOff && hasFeature(config, KEY_PAGE_FEATURE);
  /** Desktop: the key page is open in the browser and the app waits for its answer. */
  const [waitingKey, setWaitingKey] = useState(false);

  // Leaving the page ends a request that is still waiting, and drops a sign-in waiting for its two-step login.
  useEffect(
    () => () => {
      deviceRun.current?.cancel();
      keyPageWaiter.cancel();
      cancelPendingSignIn();
    },
    [],
  );

  // Signed in: the vault, or the "requires two-step login" screen on the way to it. A device sign-in first shows which
  // account it reached.
  if ((status === "unlocked" || status === "two-step") && !device) return <Navigate to={next} replace />;

  function showTwoStep(token: string, providers: string[]) {
    const usable = usableProviders(providers, handOff);
    setTwoFactor({ token, providers: usable });
    setProvider(usable[0] ?? "recovery");
    setHint(
      providers.includes("passkey") && !usable.includes("passkey") && usable.every((p) => p === "recovery")
        ? "This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault in a browser."
        : null,
    );
  }

  /** A device sign-in's approval arrived (after two-step login, if the account uses it): the approving app's code is next. */
  function askDeviceCode() {
    setTwoFactor(null);
    setCode("");
    setError(null);
    setNotice(null);
    setDevice({ step: "confirm", email: email.trim() });
  }

  /** After a two-step login: the vault, or for a device sign-in the account it reached. */
  function signedIn() {
    if (device) {
      setTwoFactor(null);
      setDevice({ step: "done", email: getState().email || email });
    } else nav(next, { replace: true });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const typed = secretKey.trim();
    const remembered = typed ? null : rememberedSecretKey(email);
    try {
      const r = await login(email, password, typed || remembered);
      if (r.done) nav(next, { replace: true });
      else showTwoStep(r.twoFactorToken, r.providers);
    } catch (err) {
      const msg = errorMessage(err);
      if (msg === "secret_key_required") {
        setNeedSecretKey(true);
        setError("This account uses a Secret Key. Enter it from your Emergency Kit.");
      } else if (hasErrorCode(err, "email_not_verified")) {
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

  /** Ask a device where the account is signed in to approve this one (the request lives only on this page). */
  function startDevice() {
    const input = emailInput.current;
    if (input && !input.checkValidity()) {
      input.reportValidity();
      return;
    }
    deviceRun.current?.cancel();
    setError(null);
    setNotice(null);
    setHint(null);
    setTwoFactor(null);
    setDevice({ step: "asking" });
    // Only the latest run's news counts ("Try again" starts another).
    const turn = {};
    deviceTurn.current = turn;
    deviceRun.current = startDeviceLogin(email.trim(), (s) => {
      if (deviceTurn.current !== turn) return;
      if (s.step === "two-step") showTwoStep(s.token, s.providers);
      setDevice(s);
    });
  }

  /** Back to the master password form; a request still waiting is dropped. */
  function stopDevice() {
    deviceRun.current?.cancel();
    deviceRun.current = null;
    deviceTurn.current = null;
    cancelPendingSignIn();
    setDevice(null);
    setTwoFactor(null);
    setCode("");
    setError(null);
    setNotice(null);
    setHint(null);
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    if (!twoFactor) return;
    setBusy(true);
    setError(null);
    try {
      if ((await verifyTwoFactor(twoFactor.token, provider, code, remember)) === "confirm") askDeviceCode();
      else signedIn();
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

  /** Desktop: open the server's key page in the browser and wait for it to hand the signed assertion back. */
  async function securityKeyHandOff(token: string): Promise<TwoStepOutcome | null> {
    const start = await startTwoFactorPasskey(token);
    // Only the connected server's own page (https, host = relying party = this server's host).
    const page = keyPageUrl(start.key_page, start.options, "app", server.origin());
    if (!page || !desktop) throw new Error(KEY_PAGE_MISMATCH);
    const answer = keyPageWaiter.expect(start.options, page.state);
    setWaitingKey(true);
    try {
      await desktop.openUrl(page.url);
    } catch (e) {
      keyPageWaiter.cancel();
      throw e;
    }
    const credential = await answer;
    setWaitingKey(false);
    // Cancelled (on the page or here): back to the choice, without an error.
    if (!credential) return null;
    return finishTwoFactorPasskey(token, credential, remember);
  }

  async function securityKey() {
    if (!twoFactor) return;
    setBusy(true);
    setError(null);
    try {
      const outcome = handOff ? await securityKeyHandOff(twoFactor.token) : await verifyTwoFactorPasskey(twoFactor.token, remember);
      if (outcome === "confirm") askDeviceCode();
      else if (outcome === "done") signedIn();
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setWaitingKey(false);
      setBusy(false);
    }
  }

  const usePasskey = provider === "passkey";

  const pickProvider = (p: string) => (keyPageWaiter.cancel(), setProvider(p), setCode(""), setError(null));
  const startOver = () => {
    keyPageWaiter.cancel();
    if (device) return stopDevice();
    setTwoFactor(null);
    setCode("");
    setError(null);
    setNotice(null);
    setHint(null);
    cancelPendingSignIn();
  };

  const done = device?.step === "done" ? device.email : null;
  const title = done ? "You're signed in" : twoFactor ? "Two-step login" : device ? "Sign in with another device" : "Sign in to PassAuth";

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>{title}</h1>
          {(twoFactor || device) && !done && <p className="muted wrap-anywhere">{email.trim()}</p>}
        </div>

        {done ? (
          <SignedInPanel
            email={done}
            onContinue={() => nav(next, { replace: true })}
            onSignOut={async () => {
              await logout();
              stopDevice();
            }}
          />
        ) : twoFactor ? (
          <form className="auth-panel stack" onSubmit={submitCode} data-two-step>
            {twoFactor.providers.length > 1 && (
              <fieldset className="choice-group">
                <legend className="field-label">Verify with</legend>
                <div className="choices choices-compact">
                  {twoFactor.providers.map((p) => (
                    <label key={p} className="choice">
                      <span className="tile" aria-hidden="true">
                        <Icon name={PROVIDER_ICON[p] ?? "shield"} />
                      </span>
                      <span className="choice-text">
                        <span className="choice-title">{PROVIDER_LABEL[p] ?? p}</span>
                      </span>
                      <input type="radio" name="provider" value={p} checked={provider === p} onChange={() => pickProvider(p)} />
                    </label>
                  ))}
                </div>
              </fieldset>
            )}
            {device && (
              <div className="alert alert-ok small" role="status">
                Your other device approved this sign-in. Finish it with your second step.
              </div>
            )}
            {usePasskey ? (
              <p className="card-text">
                {handOff
                  ? "PassAuth opens your server's page in the browser. Touch your security key or use your passkey there."
                  : "Insert or tap your security key, or use the fingerprint, face or PIN prompt on this device."}
              </p>
            ) : (
              <div className="field">
                <label htmlFor="two-step-code">{provider === "recovery" ? "Recovery code" : provider === "email" ? "Code from the email" : "6-digit code from your authenticator app"}</label>
                <input
                  id="two-step-code"
                  key={provider}
                  className="input mono code-entry"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputMode={provider === "recovery" ? "text" : "numeric"}
                  autoComplete="one-time-code"
                  autoFocus
                  required
                />
                {provider === "email" && (
                  <button type="button" className="btn btn-text editor-add" onClick={emailCode}>
                    <Icon name="mail" /> Email me a code
                  </button>
                )}
              </div>
            )}
            {hint && (
              <div className="alert alert-info" role="note">
                {hint}
              </div>
            )}
            {notice && (
              <div className="alert alert-ok" role="status">
                {notice}
              </div>
            )}
            <label className="check small">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
              <span>Don't ask again on this device for 30 days</span>
            </label>
            <ErrorText error={error} />
            <SheetActions
              quiet={
                <button type="button" className="btn btn-text" onClick={startOver}>
                  Use a different account
                </button>
              }
            >
              {usePasskey && waitingKey ? (
                <>
                  <p className="muted small" role="status">
                    Waiting for your security key…
                  </p>
                  <p className="small">{KEY_PAGE_WARNING}</p>
                  <button type="button" className="btn btn-block" onClick={() => keyPageWaiter.cancel()}>
                    Cancel
                  </button>
                </>
              ) : usePasskey ? (
                <button type="button" className="btn btn-accent btn-block" disabled={busy} onClick={securityKey} autoFocus>
                  {busy ? "Waiting for your security key…" : "Use security key"}
                </button>
              ) : (
                <button className="btn btn-accent btn-block" disabled={busy || !code}>
                  {busy ? "Verifying…" : "Verify and sign in"}
                </button>
              )}
            </SheetActions>
          </form>
        ) : device?.step === "confirm" ? (
          <DeviceCodePanel
            onDone={(reached) => setDevice({ step: "done", email: reached })}
            onStopped={() => {
              stopDevice();
              setError(CODE_STOPPED);
            }}
            onCancel={stopDevice}
          />
        ) : device ? (
          <DevicePanel state={device} onRetry={startDevice} onCancel={stopDevice} />
        ) : (
          <form className="auth-panel stack" onSubmit={submit}>
            <label className="field">
              <span>Email</span>
              <input
                ref={emailInput}
                className="input"
                type="email"
                name="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                required
                autoFocus={!email}
              />
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
            <ErrorText error={outdated ? SERVER_UPDATE_NEEDED : error} />
            <SheetActions
              quiet={
                <>
                  {canUseDevice && (
                    <button type="button" className="btn btn-text" onClick={startDevice}>
                      Sign in with another device
                    </button>
                  )}
                  {config?.signups_allowed !== false && !outdated && (
                    <Link className="btn btn-text" to="/register">
                      Create an account
                    </Link>
                  )}
                </>
              }
            >
              <button className="btn btn-accent btn-block" disabled={busy || outdated || !email || !password}>
                {busy ? "Signing in…" : "Sign in"}
              </button>
            </SheetActions>
          </form>
        )}

        {desktop && !done && (
          <p className="auth-foot">
            Connected to {server.host()}.{" "}
            <button type="button" className="link" onClick={() => desktop.changeServer()}>
              Change server
            </button>
          </p>
        )}
      </div>
    </main>
  );
}

/** A request on its way, waiting for its answer, or ended without a sign-in. */
function DevicePanel({ state, onRetry, onCancel }: { state: DeviceLoginState; onRetry: () => void; onCancel: () => void }) {
  const now = useNow(state.step === "waiting" ? 1000 : null);
  const backToPassword = (
    <button type="button" className="btn btn-text" onClick={onCancel}>
      Use your master password
    </button>
  );
  const ended = (message: string) => (
    <div className="auth-panel stack">
      <div className="alert alert-error" role="alert">
        {message}
      </div>
      <SheetActions quiet={backToPassword}>
        <button type="button" className="btn btn-accent btn-block" onClick={onRetry} autoFocus>
          Try again
        </button>
      </SheetActions>
    </div>
  );

  switch (state.step) {
    case "waiting": {
      const left = state.deadline - now;
      return (
        <div className="auth-panel stack">
          <p className="card-text">
            On a device where you're already signed in, approve this sign-in and choose these words there. Then enter the code it shows.
          </p>
          <LoginPhrase phrase={state.phrase} />
          <div className="stack-s">
            <p className="small" role="status">
              Waiting for approval…
            </p>
            <p className="small muted">
              {left > 0 ? (
                <>
                  This request expires in <span className="countdown">{countdown(left)}</span>.
                </>
              ) : (
                "This request is about to expire."
              )}{" "}
              Nothing on your other device? Unlock PassAuth there, or open Settings, then Sessions.
            </p>
          </div>
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={onCancel}>
                Cancel
              </button>
            }
          />
        </div>
      );
    }
    case "denied":
      return ended("This sign-in was denied on your other device.");
    case "expired":
      return ended("This request expired before it was approved. Requests last 15 minutes.");
    case "used":
      return ended("This request was already used. Start a new one.");
    case "failed":
      return ended(friendlyError(state.error));
    default:
      // Asking, signing in, or handing over to two-step login.
      return (
        <div className="auth-panel stack">
          <p className="card-text" role="status">
            {state.step === "signing-in" ? "Approved. Signing in…" : "Sending the sign-in request…"}
          </p>
          {state.step === "asking" && (
            <SheetActions
              quiet={
                <button type="button" className="btn btn-text" onClick={onCancel}>
                  Cancel
                </button>
              }
            />
          )}
        </div>
      );
  }
}

/**
 * The approval arrived: it becomes usable only with the code the approving app shows (`confirmDeviceLogin`), which a
 * server can't make up. Three wrong codes stop the sign-in (`onStopped`); Cancel drops it.
 */
function DeviceCodePanel({ onDone, onStopped, onCancel }: { onDone: (email: string) => void; onStopped: () => void; onCancel: () => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!codeDigits(code)) return setError(CODE_FORMAT);
    setBusy(true);
    setError(null);
    try {
      const r = await confirmDeviceLogin(code);
      if (r.kind === "done") return onDone(r.email);
      if (r.kind === "stopped") return onStopped();
      setError(wrongCodeText(r.attemptsLeft));
      setCode("");
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="auth-panel stack" onSubmit={submit}>
      <div className="alert alert-ok small" role="status">
        Your other device approved this sign-in.
      </div>
      <div className="field">
        <label htmlFor="device-code">Enter the 6-digit code shown on your other device</label>
        <input
          id="device-code"
          className="input mono code-entry"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={9}
          spellCheck={false}
          autoFocus
          required
        />
        <span className="field-hint">It shows right after you approve there. The code proves the approval came from your other device.</span>
      </div>
      <ErrorText error={error} />
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        }
      >
        <button className="btn btn-accent btn-block" disabled={busy || !code.trim()}>
          {busy ? "Checking…" : "Continue"}
        </button>
      </SheetActions>
    </form>
  );
}

/** The account a device sign-in reached: shown before the vault opens, so the user can tell it is theirs. */
function SignedInPanel({ email, onContinue, onSignOut }: { email: string; onContinue: () => void; onSignOut: () => void }) {
  return (
    <div className="auth-panel stack">
      <div className="signed-in-as" role="status">
        <span className="small muted">Signed in as</span>
        <strong>{email}</strong>
      </div>
      <p className="card-text">Check that this is your account before you save anything in it.</p>
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={onSignOut}>
            Not your account? Sign out
          </button>
        }
      >
        <button type="button" className="btn btn-accent btn-block" onClick={onContinue} autoFocus>
          Continue
        </button>
      </SheetActions>
    </div>
  );
}
