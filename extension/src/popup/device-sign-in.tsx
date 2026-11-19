/**
 * "Sign in with another device" (servers with `login_with_device`): this browser asks the account's server to let a
 * device where the user is signed in approve the sign-in, shows the five words of its own request key large, with a
 * countdown, and waits. The request's key can't be saved (core `LoginRequestKey`, memory only), so the request runs in
 * this page: the toolbar popup closes whenever the browser loses focus, so the sign-in screen moves it to PassAuth's
 * own window first (`?popout=1&device=1`), which stays open while the user approves elsewhere. The web vault's state
 * machine runs it (`runDeviceLogin`: polling with the access code in a header, backing off, giving up when it
 * expires); the worker carries its requests (background/device-sign-in.ts). An approval opens here with this
 * request's key, and then asks for the 6-digit code the approving device shows (core `ApprovedLogin.confirm`: three
 * wrong codes stop the sign-in for good): only then is the account bundle unlocked and the worker finishes the
 * sign-in like a password one. With two-step login the key is kept until that code is verified. A Secret Key that
 * came along is kept only for the email typed here, and never over a different one kept for it already.
 */

import { LogoMark } from "@web/components/Logo";
import { ErrorText, Icon, SheetActions } from "@web/components/ui";
import {
  type Approval,
  CODE_FORMAT,
  CODE_STOPPED,
  type CodeOutcome,
  checkCode,
  countdown,
  type DeviceLoginRun,
  type DeviceLoginState,
  type DeviceSession,
  runDeviceLogin,
  sleep,
  wrongCodeText,
} from "@web/lib/device-login";
import type { LoginFinishResponse } from "@web/lib/types";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { messageOf } from "../shared/errors";
import { callPopup } from "../shared/protocol";
import type { DeviceSignIn as DeviceSignInResult } from "../shared/types";
import type { ApprovedLogin, LoginRequestKey } from "../wasm/passauth_core";
import { popupCore } from "./core";
import { KEY_PAGE_TEXT, KEY_PAGE_WARNING, msg, PROVIDER_ICONS, PROVIDER_TITLES } from "./ctx";
import { Choices, Tile } from "./sheet";
import { Phrase } from "./sign-in-requests";

/** Shown when an approval doesn't open with this request's key, or doesn't fit the account. */
const KEY_UNUSABLE = "This sign-in couldn't be finished: the approval doesn't match the request this browser made. Start again, and check that both devices show the same words.";

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

/** The query of a PassAuth window started for "Sign in with another device" (`?popout=1&device=1&email=…`). */
export function deviceSignInEmail(): string | null {
  const q = new URLSearchParams(location.search);
  return q.has("popout") && q.get("device") === "1" ? (q.get("email") ?? "") : null;
}

/** Open the sign-in in PassAuth's own window (it stays open while the user approves on another device). */
export function deviceSignInUrl(email: string): string {
  return chrome.runtime.getURL(`popup.html?popout=1&device=1&email=${encodeURIComponent(email)}`);
}

/** An approval opened with this request's key, waiting for the code the approving device shows. */
interface Opened {
  approved: ApprovedLogin;
  session: DeviceSession;
  account: string;
  /** The email typed on this device (the Secret Key that came along is kept only for it). */
  email: string;
}

/** Sign the session the approval brought out again (best effort) and drop the approval: nothing of it is kept. */
function discard(o: Pick<Opened, "account" | "session"> & { approved?: ApprovedLogin }) {
  void callPopup("deviceSignIn:discard", { account: o.account, accessToken: o.session.access_token }).catch(() => {});
  o.approved?.free();
}

/**
 * Open the approval's sealed key with this request's key (used up, freed here). It unlocks nothing yet: the code from
 * the approving device comes first (`confirmCode`). A session whose approval doesn't open is signed out again.
 */
function openApproval(key: LoginRequestKey, requestId: string, account: string, email: string, s: DeviceSession): Opened {
  try {
    return { approved: key.open(s.sealed_key, s.user_id, requestId), session: s, account, email };
  } catch {
    discard({ account, session: s });
    throw new Error(KEY_UNUSABLE);
  } finally {
    key.free();
  }
}

/** What `confirmCode` made of a code: signed in, wrong (with the tries left), not a code at all, or stopped for good. */
type CodeResult = { ok: true; email: string } | { ok: false; error: string; stopped?: boolean };

/**
 * Check the code the approving device shows (6 digits; spaces and hyphens are fine), by the web vault's rule
 * (`checkCode`); right → unlock the account bundle and hand the account to the worker, which signs in. Anything but 6
 * digits isn't counted; the third wrong code stops the sign-in: its session is signed out again and nothing is kept.
 */
async function confirmCode(o: Opened, code: string): Promise<CodeResult> {
  let outcome: CodeOutcome;
  try {
    outcome = checkCode(o.approved, code);
  } catch (e) {
    return { ok: false, error: messageOf(e) === CODE_FORMAT ? CODE_FORMAT : msg(e) };
  }
  if (outcome.kind === "stopped") {
    discard(o);
    return { ok: false, error: CODE_STOPPED, stopped: true };
  }
  if (outcome.kind === "wrong") return { ok: false, error: wrongCodeText(outcome.attemptsLeft) };
  const s = o.session;
  let signIn: DeviceSignInResult;
  try {
    const unlocked = o.approved.unlock(s.bundle);
    try {
      const secretKey = o.approved.secretKey();
      signIn = {
        email: s.email,
        accessToken: s.access_token,
        refreshToken: s.refresh_token,
        bundle: s.bundle,
        accountId: o.approved.accountId,
        keys: b64(unlocked.toSessionBytes()),
        ...(secretKey ? { secretKey } : {}),
        ...(s.remember_token ? { rememberToken: s.remember_token } : {}),
      };
    } finally {
      unlocked.free();
    }
  } catch {
    discard(o);
    return { ok: false, error: KEY_UNUSABLE, stopped: true };
  }
  o.approved.free();
  await callPopup("deviceSignIn:finish", { account: o.account, signIn, typedEmail: o.email });
  return { ok: true, email: s.email };
}

/**
 * The session part of a two-step answer, with the sealed key it carries (null when it isn't one). What goes to the
 * core must be text: a number or object there would trap it (or make its glue allocate memory it never frees).
 */
function sessionOf(r: LoginFinishResponse & { sealed_key?: unknown }): DeviceSession | null {
  const sealed = typeof r.sealed_key === "string" ? r.sealed_key : "";
  const text = (v: unknown) => typeof v === "string" && v !== "";
  if (!sealed || !text(r.access_token) || !text(r.refresh_token) || !text(r.user_id) || !text(r.email) || !r.bundle || typeof r.bundle !== "object") return null;
  return {
    user_id: r.user_id,
    email: r.email,
    access_token: r.access_token,
    refresh_token: r.refresh_token,
    bundle: r.bundle,
    sealed_key: sealed,
    ...(r.remember_token ? { remember_token: r.remember_token } : {}),
  };
}

/** A key kept for the two-step answer, with the request it belongs to. */
interface Held {
  key: LoginRequestKey;
  requestId: string;
  account: string;
}

/**
 * The request's screens. `onDone(email)`: signed in (the popup shows the vault, saying which account it reached);
 * `onBack`: back to the sign-in form.
 */
export function DeviceSignIn({ email, onDone, onBack }: { email: string; onDone: (email: string) => void; onBack: () => void }) {
  const [state, setState] = useState<DeviceLoginState>({ step: "asking" });
  const [now, setNow] = useState(() => Date.now());
  const run = useRef<DeviceLoginRun | null>(null);
  const held = useRef<Held | null>(null);
  /** The approval waiting for its code, and how the run hears that it was confirmed (or stopped). */
  const [opened, setOpened] = useState<{ o: Opened; settle: (r: CodeResult) => void } | null>(null);
  const openedRef = useRef<Opened | null>(null);
  const [attempt, setAttempt] = useState(0);

  const drop = useCallback(() => {
    run.current?.cancel();
    run.current = null;
    held.current?.key.free();
    held.current = null;
    // Left while the code was asked for: the session that came is signed out again, nothing is kept.
    if (openedRef.current) discard(openedRef.current);
    openedRef.current = null;
    setOpened(null);
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: one run per attempt ("Try again" starts a new one)
  useEffect(() => {
    let alive = true;
    setState({ step: "asking" });
    (async () => {
      const core = await popupCore();
      const begin = await callPopup("deviceSignIn:start", { email });
      if (!alive) return;
      const account = begin.account;
      run.current = runDeviceLogin(
        email,
        {
          newKey: () => core.LoginRequestKey.generate(),
          randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
          device: begin.device,
          rememberToken: begin.rememberToken,
          create: (body) => callPopup("deviceSignIn:create", { account, body }),
          poll: (id, accessCode) => callPopup("deviceSignIn:poll", { account, id, accessCode }),
          async finish(approval: Approval, key: LoginRequestKey, requestId: string) {
            if (approval.kind === "two-step") {
              held.current = { key, requestId, account };
              return;
            }
            // The code from the approving device first: the run waits here until it is confirmed (or stopped).
            const o = openApproval(key, requestId, account, email, approval.session);
            openedRef.current = o;
            const result = await new Promise<CodeResult>((settle) => setOpened({ o, settle }));
            openedRef.current = null;
            setOpened(null);
            if (!result.ok) throw new Error(result.error);
          },
          discard: (session) => void callPopup("deviceSignIn:discard", { account, accessToken: session.access_token }).catch(() => {}),
          now: Date.now,
          sleep,
        },
        (s) => {
          if (alive) setState(s);
        },
      );
    })().catch((error: unknown) => {
      if (alive) setState({ step: "failed", error });
    });
    return () => {
      alive = false;
      drop();
    };
  }, [attempt]);

  // The countdown, and a poll right away when the window is shown again.
  useEffect(() => {
    if (state.step !== "waiting") return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    const visible = () => document.visibilityState === "visible" && run.current?.pollNow();
    document.addEventListener("visibilitychange", visible);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [state.step]);

  // Signed in: said once (the popup then shows the vault).
  const reported = useRef(false);
  useEffect(() => {
    if (state.step !== "done" || reported.current) return;
    reported.current = true;
    onDone(state.email);
  }, [state, onDone]);

  const again = () => {
    drop();
    setAttempt((n) => n + 1);
  };
  const back = () => {
    drop();
    onBack();
  };

  if (state.step === "two-step") return <TwoStep email={email} challenge={state} held={held} onDone={onDone} onBack={back} />;
  if (opened) return <ConfirmCode email={email} opened={opened.o} onResult={opened.settle} onBack={back} />;

  const head = (title: string, sub?: string) => (
    <div className="auth-head">
      <LogoMark size={48} />
      <h1>{title}</h1>
      {sub && <p className="auth-sub">{sub}</p>}
    </div>
  );
  const retry = (
    <SheetActions
      quiet={
        <button type="button" className="btn btn-text" onClick={back}>
          Back to sign-in
        </button>
      }
    >
      <button type="button" className="btn btn-primary btn-block" onClick={again}>
        Try again
      </button>
    </SheetActions>
  );

  switch (state.step) {
    case "asking":
    case "signing-in":
      return (
        <div className="pop-auth" aria-busy="true">
          {head(state.step === "asking" ? "Asking your server…" : "Signing in…", email)}
        </div>
      );
    case "waiting":
      return (
        <div className="pop-auth">
          {head("Approve on your other device", email)}
          <p className="card-text">
            Open PassAuth where you're signed in to this account — the web vault, the desktop or phone app, or the extension in another browser — and approve the sign-in there. Check that it shows
            these five words:
          </p>
          <Phrase phrase={state.phrase} />
          <p className="pop-countdown">
            The request expires in <span className="countdown">{countdown(state.deadline - now)}</span>. Keep this window open.
          </p>
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={back}>
                Cancel
              </button>
            }
          />
        </div>
      );
    case "denied":
      return (
        <div className="pop-auth">
          {head("The sign-in was denied", "It was denied on your other device. If that wasn't you, nothing was signed in.")}
          {retry}
        </div>
      );
    case "expired":
    case "used":
      return (
        <div className="pop-auth">
          {head(state.step === "expired" ? "The request expired" : "This request was already used", "Start again, and approve it within 15 minutes.")}
          {retry}
        </div>
      );
    case "failed":
      return (
        <div className="pop-auth">
          {head("This sign-in didn't work")}
          <ErrorText error={msg(state.error)} />
          {retry}
        </div>
      );
    default:
      return <div className="pop-auth" />;
  }
}

/** Two-step login after the approval: the code, then the session with the sealed key, opened with the kept request key. */
function TwoStep({
  email,
  challenge,
  held,
  onDone,
  onBack,
}: {
  email: string;
  challenge: { token: string; providers: string[] };
  held: { current: Held | null };
  onDone: (email: string) => void;
  onBack: () => void;
}) {
  // A security key works through the server's key page where the server offers it; otherwise the other methods only.
  const [keyPage, setKeyPage] = useState(false);
  const providers = challenge.providers.filter((p) => (p === "passkey" ? keyPage : p === "totp" || p === "email" || p === "recovery"));
  const [provider, setProvider] = useState(providers[0] ?? "recovery");
  /** The key window is open; this answer waits for it. */
  const [waitingKey, setWaitingKey] = useState(false);
  const [code, setCode] = useState("");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Opened | null>(null);
  const [stopped, setStopped] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: once, for the account this run signs in to
  useEffect(() => {
    const account = held.current?.account;
    const offered = account && challenge.providers.includes("passkey") ? callPopup("deviceSignIn:keyPage", { account }).catch(() => false) : Promise.resolve(false);
    void offered.then((yes) => {
      setKeyPage(yes);
      if (yes && !challenge.providers.some((p) => p === "totp" || p === "email")) setProvider("passkey");
      else if (!yes && challenge.providers.includes("passkey") && !challenge.providers.some((p) => p === "totp" || p === "email"))
        setNote("This account uses a security key for two-step login, which this app doesn't support yet. Use a recovery code, or sign in with the web vault.");
    });
  }, []);

  /** The second step passed: open the approval with the kept request key. */
  function approved(h: Held, r: LoginFinishResponse) {
    const session = sessionOf(r);
    if (!session) throw new Error("Your server didn't send the approved key. Start again.");
    held.current = null;
    setOpened(openApproval(h.key, h.requestId, h.account, email, session));
  }

  async function withKey() {
    const h = held.current;
    if (!h) return setError("This sign-in expired. Start again.");
    setError(null);
    setWaitingKey(true);
    try {
      const r = await callPopup("deviceSignIn:verifyKey", { account: h.account, token: challenge.token, remember });
      setWaitingKey(false);
      // Cancelled (the key window closed): back to the choice.
      if (r) approved(h, r);
    } catch (err) {
      setWaitingKey(false);
      setError(msg(err));
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    if (provider === "passkey") return void withKey();
    const h = held.current;
    if (!h) return setError("This sign-in expired. Start again.");
    setBusy(true);
    setError(null);
    try {
      approved(h, await callPopup("deviceSignIn:verify2fa", { account: h.account, token: challenge.token, provider, code, remember }));
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }

  // The second step passed: now the code from the approving device.
  if (opened) {
    return (
      <ConfirmCode
        email={email}
        opened={opened}
        onResult={(r) => {
          if (r.ok) onDone(r.email);
          else if (r.stopped) setStopped(r.error);
        }}
        onBack={() => {
          discard(opened);
          onBack();
        }}
      />
    );
  }
  if (stopped) {
    return (
      <div className="pop-auth">
        <div className="auth-head">
          <h1>This sign-in didn't work</h1>
        </div>
        <ErrorText error={stopped} />
        <SheetActions>
          <button type="button" className="btn btn-primary btn-block" onClick={onBack}>
            Back to sign-in
          </button>
        </SheetActions>
      </div>
    );
  }

  if (waitingKey) {
    return (
      <div className="pop-auth">
        <div className="auth-head">
          <h1>Two-step login</h1>
          <p className="auth-sub">{email}</p>
        </div>
        <p className="card-text" role="status">
          Waiting for your security key…
        </p>
        <p className="card-text">{KEY_PAGE_WARNING}</p>
        <SheetActions>
          <button type="button" className="btn btn-ghost btn-block" onClick={() => void callPopup("twoStepKey:cancel").catch((e) => setError(msg(e)))}>
            Cancel
          </button>
        </SheetActions>
      </div>
    );
  }

  const usingKey = provider === "passkey";
  return (
    <form className="pop-auth" onSubmit={verify}>
      <div className="auth-head">
        <h1>Two-step login</h1>
        <p className="auth-sub">{email}</p>
      </div>
      <p className="card-text">Your other device approved the sign-in. Your account also asks for a second step.</p>
      {providers.length > 1 && (
        <Choices
          compact
          label="Verify with"
          value={provider}
          onChange={setProvider}
          options={providers.map((p) => ({
            id: p,
            title: PROVIDER_TITLES[p] ?? p,
            icon: (
              <Tile>
                <Icon name={PROVIDER_ICONS[p] ?? "key"} />
              </Tile>
            ),
          }))}
        />
      )}
      {usingKey ? (
        <p className="card-text">{KEY_PAGE_TEXT}</p>
      ) : (
        <label className="field">
          <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
          <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
        </label>
      )}
      {note && (
        <div className="alert alert-info" role="status">
          {note}
        </div>
      )}
      <label className="check small">
        <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
        <span>Remember this browser for 30 days</span>
      </label>
      <ErrorText error={error} />
      <SheetActions
        quiet={
          <>
            {provider === "email" && (
              <button
                type="button"
                className="btn btn-text"
                onClick={() =>
                  callPopup("email2fa", { token: challenge.token }).then(
                    () => setNote(`Code sent to ${email}.`),
                    (e) => setError(msg(e)),
                  )
                }
              >
                Email me a code
              </button>
            )}
            <button type="button" className="btn btn-text" onClick={onBack}>
              Cancel
            </button>
          </>
        }
      >
        {usingKey ? (
          <button type="submit" className="btn btn-primary btn-block">
            Use security key
          </button>
        ) : (
          <button type="submit" className="btn btn-primary btn-block" disabled={busy || !code}>
            {busy ? "Verifying…" : "Verify and sign in"}
          </button>
        )}
      </SheetActions>
    </form>
  );
}

/**
 * "Enter the 6-digit code shown on your other device." The approving device shows it once the user picked the right
 * words there; nothing is unlocked here before it is confirmed. A wrong code says how many tries are left; the third
 * stops the sign-in (`onResult` with `stopped`).
 */
function ConfirmCode({ email, opened, onResult, onBack }: { email: string; opened: Opened; onResult: (r: CodeResult) => void; onBack: () => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    let r: CodeResult;
    try {
      r = await confirmCode(opened, code);
    } catch (err) {
      r = { ok: false, error: msg(err), stopped: true };
    }
    if (!r.ok) {
      setError(r.error);
      setBusy(false);
      if (!r.stopped) return setCode("");
    }
    onResult(r);
  }

  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="auth-head">
        <LogoMark size={48} />
        <h1>Enter the code</h1>
        <p className="auth-sub">{email}</p>
      </div>
      <p className="card-text">Your other device approved the sign-in. Enter the 6-digit code shown on your other device.</p>
      <label className="field">
        <span>6-digit code</span>
        <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="off" maxLength={9} autoFocus required disabled={busy} />
      </label>
      <ErrorText error={error} />
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={onBack}>
            Cancel
          </button>
        }
      >
        <button type="submit" className="btn btn-primary btn-block" disabled={busy || !code.trim()}>
          {busy ? "Checking…" : "Sign in"}
        </button>
      </SheetActions>
    </form>
  );
}
