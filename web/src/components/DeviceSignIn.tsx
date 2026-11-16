// Approve a sign-in from another device: the five words both screens show, the approval sheet of an unlocked app and
// the list of waiting requests in Settings → Sessions (`lib/device-login.ts` has the rules).
import { Fragment, useEffect, useMemo, useState } from "react";
import { loginPhraseChoices } from "../wasm/passauth_core";
import { friendlyError } from "../lib/api";
import { clientInfo, deviceKindInfo } from "../lib/clients";
import {
  REQUEST_CHANGED,
  REQUEST_EXPIRED,
  WORDS_MISMATCH,
  groupedCode,
  phraseChoices,
  phraseWords,
  requestOrigin,
  type AnswerOutcome,
  type SignInRequest,
} from "../lib/device-login";
import {
  CantApproveError,
  answerSignInRequest,
  dismissApprovalNotice,
  onShownRequestEnded,
  putOffSignInRequest,
  refreshSignInRequests,
  reviewSignInRequest,
  useSignInRequests,
} from "../lib/device-login-client";
import { useVault } from "../lib/vault";
import { ErrorText, Icon, Modal, SheetActions, toast, type IconName } from "./ui";

/** The five words of a sign-in request, large enough to compare at a glance. The same on both screens. */
export function LoginPhrase({ phrase }: { phrase: string }) {
  return (
    <ol className="login-phrase" aria-label="The five words">
      {phraseWords(phrase).map((word, i) => (
        <li key={i}>{word}</li>
      ))}
    </ol>
  );
}

/** Five words as the content of a button to choose them (spaces between them, for screen readers). */
function PhraseChoiceWords({ phrase }: { phrase: string }) {
  return (
    <span className="phrase-choice-words">
      {phraseWords(phrase).map((word, i) => (
        <Fragment key={i}>
          {i > 0 && " "}
          <span>{word}</span>
        </Fragment>
      ))}
    </span>
  );
}

/** "9:14 PM", with the date when it isn't today. */
function requestTime(seconds: number): string {
  const d = new Date(seconds * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString(undefined, { timeStyle: "short" }) : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** The app that asks, as it says ("Web", "Desktop app 0.7.0"), else its kind of device. */
function requestApp(req: SignInRequest): { label: string; icon: IconName } {
  const client = clientInfo(req.client);
  const kind = deviceKindInfo(req.deviceKind);
  return { label: client?.label ?? kind.label, icon: client?.icon ?? kind.icon ?? "shield" };
}

const OUTCOME_NOTE: Record<Exclude<AnswerOutcome, "done">, string> = {
  expired: REQUEST_EXPIRED,
  answered: "This sign-in request was already answered in another window or on another device.",
  gone: "This sign-in request isn't waiting any more.",
};
const ENDED_NOTE: Record<"answered" | "expired", string> = {
  answered: "This sign-in request was answered in another window or on another device.",
  expired: REQUEST_EXPIRED,
};

/** The words to choose from take a press only this long after they appear, and after the app comes back into view. */
const ARM_DELAY_MS = 1000;

/**
 * False for `ms` after the component appears, and again for `ms` whenever the page becomes visible or the window gains
 * focus: a click or key press meant for something else must never land on a choice that just came up.
 */
function useArmed(ms: number): boolean {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    let timer = window.setTimeout(() => setArmed(true), ms);
    const restart = () => {
      setArmed(false);
      window.clearTimeout(timer);
      timer = window.setTimeout(() => setArmed(true), ms);
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") restart();
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", restart);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", restart);
    };
  }, [ms]);
  return armed;
}

/**
 * The approval sheet of an unlocked app: comes up for one sign-in request of the account at a time (newest first, or
 * the one chosen in Settings) until the user approves, denies or puts it off. The request is frozen as it was when the
 * sheet came up; if a later listing changes it, the sheet closes with a note instead. After an approval, the code for
 * the new device stays up until Done. Lives in the app shell, so it shows on every page of the vault.
 */
export function SignInRequestSheet() {
  const { shown, notice } = useSignInRequests();

  useEffect(() => {
    // The app opens after unlocking: list what is waiting, also when live sync can't connect.
    void refreshSignInRequests();
    return onShownRequestEnded((why) => toast(ENDED_NOTE[why]));
  }, []);

  if (notice?.kind === "code") return <CodeNote code={notice.code} />;
  if (notice) return <ClosedNote text={notice.kind === "changed" ? REQUEST_CHANGED : WORDS_MISMATCH} denied={notice.kind === "mismatch"} />;
  if (!shown) return null;
  // Keyed by the request and its key: another request (or another key) is another sheet, never this one updated. Not
  // by its challenge, which the server seals again for every listing.
  return <ApproveSheet key={`${shown.id}\n${shown.publicKey}`} request={shown} onClose={() => putOffSignInRequest(shown.id)} />;
}

/** A request's sheet closed (it changed under it, or the words picked weren't its own): nothing else comes up until this is read. */
function ClosedNote({ text, denied }: { text: string; denied: boolean }) {
  return (
    <Modal title={denied ? "Sign-in request denied" : "Sign-in request closed"} icon="shield" tone="danger" onClose={dismissApprovalNotice}>
      <p className="card-text">{text}</p>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" onClick={dismissApprovalNotice} data-autofocus="">
          OK
        </button>
      </SheetActions>
    </Modal>
  );
}

/** After approving: the code to enter on the new device, kept on screen until Done (Escape doesn't close it). */
function CodeNote({ code }: { code: string }) {
  return (
    <Modal title="Sign-in approved" icon="shield" closable={false} onClose={() => {}}>
      <p className="card-text">Enter this code on the new device:</p>
      <p className="approval-code" aria-label={code.split("").join(" ")}>
        {groupedCode(code)}
      </p>
      <p className="small muted">The new device can open your vault only with this code. Never read it out or give it to anyone.</p>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" onClick={dismissApprovalNotice} data-autofocus="">
          Done
        </button>
      </SheetActions>
    </Modal>
  );
}

function ApproveSheet({ request, onClose }: { request: SignInRequest; onClose: () => void }) {
  const { email } = useVault();
  // Worked out here from the frozen request's own key (its words among decoys, in random order): never the server's
  // copy of the words, never a newer listing. Once per sheet, so the order doesn't change while it is up.
  const choices = useMemo(() => phraseChoices(request, loginPhraseChoices), [request]);
  const armed = useArmed(ARM_DELAY_MS);
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const app = requestApp(request);
  const close = () => {
    if (!busy) onClose();
  };

  /** `chosen`: the words picked; null for "None of these". */
  async function answer(chosen: string | null) {
    setBusy(chosen === null ? "deny" : "approve");
    setError(null);
    try {
      const outcome = await answerSignInRequest(request, chosen);
      // The request has left the list, so this sheet closes: the code (or the note that the words didn't match) comes
      // up in its place, or the next request.
      if (outcome === "done" && chosen === null) toast("Sign-in request denied.");
      else if (outcome !== "done" && outcome !== "mismatch") toast(OUTCOME_NOTE[outcome]);
    } catch (e) {
      // Put off, so this sheet is closing: the error goes where it stays visible.
      if (e instanceof CantApproveError) return toast(e.message);
      setError(friendlyError(e));
      setBusy(null);
    }
  }

  return (
    <Modal title="Sign-in request" subtitle={`Asked at ${requestTime(request.createdAt)}`} icon={app.icon} onClose={close}>
      <p className="card-text">
        A device is asking to sign in to <strong className="wrap-anywhere">{email}</strong>.
      </p>
      <dl className="claims">
        <div>
          <dt>Device (as it calls itself)</dt>
          <dd>{request.deviceName || "No name given"}</dd>
        </div>
        <div>
          <dt>App</dt>
          <dd>{app.label}</dd>
        </div>
        {request.ip && (
          <div>
            <dt>Address</dt>
            <dd>{request.ip}</dd>
          </div>
        )}
      </dl>
      {choices.length > 0 ? (
        <fieldset className="choice-group">
          <legend className="field-label">Which words does the new device show?</legend>
          <div className="choices choices-plain">
            {choices.map((c) => (
              <button key={c} type="button" className="choice phrase-choice" disabled={!armed || busy !== null} onClick={() => answer(c)}>
                <PhraseChoiceWords phrase={c} />
              </button>
            ))}
          </div>
        </fieldset>
      ) : (
        <div className="alert alert-error" role="alert">
          This request can't be checked, so it can't be approved. Choose None of these, then start again on the new device.
        </div>
      )}
      <p className="small muted">
        Choosing the words the new device shows approves the sign-in: with the code you'll see next, it can open your vault without your master
        password. If you didn't ask to sign in, or it shows other words, choose None of these.
      </p>
      {busy === "approve" && (
        <p className="small muted" role="status">
          Approving…
        </p>
      )}
      <ErrorText error={error} />
      <SheetActions
        quiet={
          <>
            <button type="button" className="btn btn-text btn-danger" disabled={busy !== null} onClick={() => answer(null)}>
              {busy === "deny" ? "Denying…" : "None of these"}
            </button>
            {/* Focused first: a stray Enter must never approve. */}
            <button type="button" className="btn btn-text" disabled={busy !== null} onClick={close} data-autofocus="">
              Not now
            </button>
          </>
        }
      />
    </Modal>
  );
}

/** Settings → Sessions: the sign-in requests waiting for an answer, each one to review in the approval sheet. */
export function SignInRequestsCard() {
  const { requests } = useSignInRequests();

  useEffect(() => {
    void refreshSignInRequests();
  }, []);

  if (requests.length === 0) return null;
  return (
    <section className="card" aria-labelledby="sign-in-requests-title">
      <div className="card-head">
        <h2 id="sign-in-requests-title">Sign-in requests</h2>
      </div>
      <p className="card-text">
        {requests.length === 1 ? "A device is" : "Devices are"} waiting for your approval to sign in. Approve only a device you're signing in on yourself. The
        names are what each device calls itself.
      </p>
      <div className="fields" role="list" aria-label="Sign-in requests">
        {requests.map((r) => {
          const app = requestApp(r);
          return (
            <div key={r.id} role="listitem">
              <span className="tile" aria-hidden="true">
                <Icon name={app.icon} />
              </span>
              <span className="grow">
                <span className="row-title">{r.deviceName || "Unknown device"}</span>
                <span className="row-sub">{requestOrigin({ deviceName: app.label, ip: r.ip }, null, `asked at ${requestTime(r.createdAt)}`)}.</span>
              </span>
              <button type="button" className="btn btn-text btn-sm" aria-label={`Review the request from ${r.deviceName || "an unknown device"}`} onClick={() => reviewSignInRequest(r.id)}>
                Review…
              </button>
            </div>
          );
        })}
      </div>
    </section>
  );
}
