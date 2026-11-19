/**
 * The server's key page (`/two-step/key`): an app that can't run WebAuthn for this server itself (desktop app,
 * extension, phone apps) opens it in a browser to use a security key or passkey for two-step login. Public, works
 * signed out, stores nothing and never sees the account. It asks its server only which sign-in waits for the challenge
 * (device, address, time) so the user can tell whether they started it, signs the allowlisted options from its fragment
 * and hands the assertion, with the app's `state`, to a fixed return target (see lib/key-page.ts).
 */
import { useEffect, useMemo, useState } from "react";
import { LogoMark } from "../components/Logo";
import { ErrorText, SheetActions } from "../components/ui";
import {
  CONTEXT_ENDED,
  CONTEXT_WARNING,
  contextLine,
  fetchContext,
  parseKeyPageFragment,
  returnTarget,
  type KeyPageContext,
  type KeyPageRequest,
  type KeyPageResult,
} from "../lib/key-page";
import { getCredential, WebAuthnError } from "../lib/webauthn";

/** Leaves this page for the return target, and asks the server (tests replace them). */
export const leave = { to: (url: string) => location.assign(url) };
export const contextSource = { fetch: (challenge: string) => fetchContext(challenge) };

export type Step = "checking" | "ended" | "ready" | "busy" | "failed" | "handed";

export function TwoStepKeyPage() {
  const request = useMemo(() => parseKeyPageFragment(location.hash, location.hostname), []);
  const [step, setStep] = useState<Step>("checking");
  const [context, setContext] = useState<KeyPageContext | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Security key · PassAuth";
    // The same tab opened again with another fragment (a new sign-in): start over from that address.
    const restart = () => location.reload();
    window.addEventListener("hashchange", restart);
    return () => window.removeEventListener("hashchange", restart);
  }, []);

  useEffect(() => {
    if (!request) return;
    let live = true;
    void contextSource.fetch(request.options.publicKey.challenge as string).then((ctx) => {
      if (!live) return;
      setContext(ctx);
      setStep(ctx ? "ready" : "ended");
    });
    return () => {
      live = false;
    };
  }, [request]);

  function finish(result: KeyPageResult) {
    if (!request) return;
    setStep("handed");
    leave.to(returnTarget(request.ret, location.origin, request.state, result));
  }

  async function use() {
    if (!request) return;
    setStep("busy");
    setError(null);
    try {
      finish({ credential: await getCredential(request.options) });
    } catch (e) {
      setError(e instanceof WebAuthnError ? e.message : "The security key didn't respond. Try again.");
      setStep("failed");
    }
  }

  return <KeyPageView request={request} step={step} context={context} error={error} now={Date.now() / 1000} onUse={use} onCancel={() => finish({ cancelled: true })} />;
}

/** What the key page shows for a state (pure, so tests can render every state). */
export function KeyPageView({
  request,
  step,
  context,
  error,
  now,
  onUse,
  onCancel,
}: {
  request: KeyPageRequest | null;
  step: Step;
  context: KeyPageContext | null;
  error: string | null;
  now: number;
  onUse: () => void;
  onCancel: () => void;
}) {
  const title = !request ? "This link isn't complete" : step === "ended" ? "This sign-in isn't waiting" : "Use your security key";
  const text = !request
    ? "Go back to the app and try again."
    : step === "ended"
      ? CONTEXT_ENDED
      : step === "handed"
        ? "Go back to PassAuth to finish signing in. You can close this window."
        : step === "checking"
          ? "Checking this sign-in…"
          : "Use your security key to finish signing in to PassAuth.";
  const offer = request && context && (step === "ready" || step === "busy" || step === "failed");

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>{title}</h1>
          <p className="muted" role={step === "checking" ? "status" : undefined}>
            {text}
          </p>
        </div>
        {offer && (
          <div className="auth-panel stack">
            <p className="card-text wrap-anywhere" data-context>
              {contextLine(context, now)}
            </p>
            <div className="alert alert-warn small" role="note">
              {CONTEXT_WARNING}
            </div>
            <ErrorText error={error} />
            <SheetActions
              quiet={
                <button type="button" className="btn btn-text" disabled={step === "busy"} onClick={onCancel}>
                  Cancel
                </button>
              }
            >
              <button type="button" className="btn btn-accent btn-block" disabled={step === "busy"} onClick={onUse} autoFocus>
                {step === "busy" ? "Waiting for your security key…" : step === "failed" ? "Try again" : "Use security key"}
              </button>
            </SheetActions>
          </div>
        )}
      </div>
    </main>
  );
}

/** `/two-step/key/done`: where the key page hands the result back to the extension, which reads it and closes the window. */
export function TwoStepKeyDonePage() {
  useEffect(() => {
    document.title = "PassAuth";
  }, []);
  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>You can close this window.</h1>
        </div>
      </div>
    </main>
  );
}
