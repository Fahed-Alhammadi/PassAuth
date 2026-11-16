/**
 * Approve a sign-in from another device, in the unlocked popup. The worker keeps the active account's waiting requests
 * (background/sign-in-requests.ts); the popup shows one at a time in a sheet: which device and app asks (as the new
 * device says: claims, cleaned and cut short), from which address and when, and "Which words does the new device
 * show?" with three sets of words to pick from (its own among decoys, core `loginPhraseChoices`, worked out in the
 * worker). Picking the right words approves and shows the 6-digit code to enter on the new device (until Done); words
 * that aren't the request's deny it; "None of these" denies, "Not now" puts it off (the sheet stays away for this
 * browser session; a notice above the list brings it back). Not now has the focus first, and the words take a press
 * only a second after the sheet appeared or the popup came back into view.
 *
 * What is on screen follows the web vault's rules (`settleQueue`, `@web/lib/device-login`): the request is frozen
 * when its sheet opens and never changes while it is shown — the approval names exactly its public key and the
 * challenge it was frozen with (the worker refuses it if the listing has another key for its id since); a listing
 * with another key for it closes the sheet with a note (and it is put off), newer requests wait in line; the code and
 * the notes stay up until read. The challenge's text is never compared: the server seals it again at every listing
 * (sign-in-queue.ts). Nothing opens by itself: with the popup closed, the toolbar badge shows a dot.
 */

import { ErrorText, Modal, SheetActions } from "@web/components/ui";
import { clientInfo, deviceKindInfo } from "@web/lib/clients";
import {
  type ApprovalNotice,
  type ApprovalQueue,
  claimedText,
  EMPTY_QUEUE,
  groupedCode,
  phraseWords,
  REQUEST_CHANGED,
  REQUEST_EXPIRED,
  type SignInRequest,
  settleQueue,
  WORDS_MISMATCH,
} from "@web/lib/device-login";
import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { REQUEST_CHANGED as CHANGED_CODE, codeOf } from "../shared/errors";
import { callPopup } from "../shared/protocol";
import { SIGN_IN_PUT_OFF_KEY, SIGN_IN_REQUESTS_PREFIX } from "../shared/storage-keys";
import type { SignInAnswer, SignInRequestView } from "../shared/types";
import { type Ctx, msg } from "./ctx";
import { keepFrozenChallenge } from "./sign-in-queue";

/** The words take a press only this long after they appear, and after the popup comes back into view. */
export const ARM_DELAY_MS = 1000;

/** The five words of a sign-in request, large enough to compare at a glance (the same on both screens). */
export function Phrase({ phrase }: { phrase: string }) {
  return (
    <ol className="pop-phrase" aria-label="The five words">
      {phraseWords(phrase).map((word, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the words of one phrase, in order; a word can repeat
        <li key={i}>{word}</li>
      ))}
    </ol>
  );
}

/** One choice's five words, spaced like the new device shows them (with real spaces between, for screen readers). */
function PhraseChoiceWords({ phrase }: { phrase: string }) {
  return (
    <span className="phrase-choice-words">
      {phraseWords(phrase).map((word, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the words of one phrase, in order; a word can repeat
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
  return today ? d.toLocaleTimeString([], { timeStyle: "short" }) : d.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

/** The app that asks ("Chrome extension 0.6.0", "Web"), else its kind of device: as the new device says, cleaned. */
const appOf = (r: SignInRequestView) => claimedText(clientInfo(r.client)?.label ?? deviceKindInfo(r.deviceKind).label);

/** The words for an answer that found the request over (the web vault's). */
const OUTCOME_NOTE: Record<Exclude<SignInAnswer["outcome"], "done" | "mismatch">, string> = {
  expired: REQUEST_EXPIRED,
  answered: "This sign-in request was already answered in another window or on another device.",
  gone: "This sign-in request isn't waiting any more.",
};
/** The shown request ended without an answer from here. */
const ANSWERED_ELSEWHERE = "This sign-in request was answered in another window or on another device.";

/** The requests put off for this browser session ("Not now", or closed because they changed). */
async function putOffIds(): Promise<Set<string>> {
  const r = await chrome.storage.session.get(SIGN_IN_PUT_OFF_KEY).catch(() => ({}) as Record<string, unknown>);
  const v = r[SIGN_IN_PUT_OFF_KEY];
  return new Set(Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
}

/** The queue's frozen request with what the worker added to it (the words to pick from), as listed when it came up. */
const asView = (r: SignInRequest | null) => r as SignInRequestView | null;

export interface SignIns {
  /** The request whose sheet is open, as frozen when it opened (it never changes while shown). */
  shown: SignInRequestView | null;
  /** The note up after a sheet closed (changed, words that didn't match, the code to enter); nothing comes up meanwhile. */
  notice: ApprovalNotice | null;
  /** Waiting requests the user put off (a notice above the list offers them again). */
  putOff: number;
  /** Show the sheet again for the put-off requests. */
  review: () => void;
  /** "Not now": the sheet stays away for this request in this browser session. */
  later: (id: string) => void;
  /** Answered here (or found over): it leaves the list; `notice` comes up in its place. */
  answered: (id: string, notice?: ApprovalNotice) => void;
  /** The worker refused it as changed: the "changed" note, and it doesn't come up again by itself. */
  changed: (id: string) => void;
  /** The note was read. */
  dismiss: () => void;
}

/**
 * The active account's waiting sign-ins: asked when the popup opens and again whenever the worker's list changes.
 * One is shown at a time, frozen (`settleQueue`); `notify` says why a shown one went by itself.
 */
export function useSignIns(activeId: string, notify: (text: string) => void): SignIns {
  /** Null until the put-off list has been read (it may say "not now" for the very request that would come up). */
  const [queue, setQueue] = useState<ApprovalQueue | null>(null);
  const current = useRef<ApprovalQueue | null>(null);
  /** Answered here: its leaving the list says nothing. */
  const answeredHere = useRef(new Set<string>());
  /** Answered lately here or elsewhere, as the worker says (`auth_request_answered`). */
  const answeredLately = useRef(new Set<string>());
  const notifyRef = useRef(notify);
  notifyRef.current = notify;

  /** `next` with what is on screen worked out again; what is put off is kept for the browser session. */
  const apply = useCallback((listed: ApprovalQueue) => {
    // A re-sealed challenge (new text at every listing) is the same request: only another key closes the sheet.
    const next = { ...listed, requests: keepFrozenChallenge(listed.requests, listed.shown) };
    const before = current.current;
    const shownId = next.shown?.id;
    const gone = shownId && !next.requests.some((r) => r.id === shownId) ? shownId : null;
    const quiet = (id: string) => answeredHere.current.has(id) || answeredLately.current.has(id);
    const { queue: q, ended } = settleQueue(next, Date.now() / 1000, quiet);
    if (ended === "expired") notifyRef.current(REQUEST_EXPIRED);
    else if (gone && !answeredHere.current.has(gone) && answeredLately.current.has(gone)) notifyRef.current(ANSWERED_ELSEWHERE);
    current.current = q;
    setQueue(q);
    if (!before || [...q.putOff].join() !== [...before.putOff].join()) {
      void chrome.storage.session.set({ [SIGN_IN_PUT_OFF_KEY]: [...q.putOff].slice(-50) }).catch(() => {});
    }
  }, []);

  useEffect(() => {
    let alive = true;
    current.current = null;
    setQueue(null);
    const load = async () => {
      const list = await callPopup("signInRequests").catch(() => null);
      if (!alive || !list) return;
      answeredLately.current = new Set(list.answered);
      const base = current.current ?? { ...EMPTY_QUEUE, putOff: await putOffIds() };
      if (!alive) return;
      const ids = new Set(list.requests.map((r) => r.id));
      apply({ ...base, requests: list.requests, putOff: new Set([...base.putOff].filter((id) => ids.has(id))) });
    };
    void load();
    const onChanged = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      if (area === "session" && `${SIGN_IN_REQUESTS_PREFIX}${activeId}` in changes) void load();
    };
    chrome.storage.onChanged.addListener(onChanged);
    return () => {
      alive = false;
      chrome.storage.onChanged.removeListener(onChanged);
    };
  }, [activeId, apply]);

  const update = useCallback(
    (fn: (q: ApprovalQueue) => ApprovalQueue) => {
      if (current.current) apply(fn(current.current));
    },
    [apply],
  );
  const later = useCallback(
    (id: string) => update((q) => ({ ...q, putOff: new Set([...q.putOff, id]), preferred: q.preferred === id ? null : q.preferred, shown: q.shown?.id === id ? null : q.shown })),
    [update],
  );
  const review = useCallback(() => update((q) => ({ ...q, putOff: new Set(), preferred: null })), [update]);
  const answered = useCallback(
    (id: string, notice?: ApprovalNotice) => {
      answeredHere.current.add(id);
      update((q) => ({ ...q, requests: q.requests.filter((r) => r.id !== id), shown: q.shown?.id === id ? null : q.shown, notice: notice ?? q.notice }));
    },
    [update],
  );
  const changed = useCallback((id: string) => update((q) => ({ ...q, putOff: new Set([...q.putOff, id]), shown: q.shown?.id === id ? null : q.shown, notice: { kind: "changed" } })), [update]);
  const dismiss = useCallback(() => update((q) => ({ ...q, notice: null })), [update]);

  const listed = queue ? new Set(queue.requests.map((r) => r.id)) : new Set<string>();
  return {
    shown: asView(queue?.shown ?? null),
    notice: queue?.notice ?? null,
    putOff: queue ? [...queue.putOff].filter((id) => listed.has(id)).length : 0,
    review,
    later,
    answered,
    changed,
    dismiss,
  };
}

/**
 * False for `ms` after the sheet appears, and again for `ms` whenever the popup comes back into view or gains the
 * focus: a click or key press meant for something else never lands on words that just came up (the web vault's rule).
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

/** The sheet for one waiting sign-in: who asks (as it says), the words to pick, None of these / Not now. */
export function SignInSheet({ ctx, request, signIns }: { ctx: Ctx; request: SignInRequestView; signIns: SignIns }) {
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const armed = useArmed(ARM_DELAY_MS);
  const close = () => {
    if (!busy) signIns.later(request.id);
  };

  /** `chosen`: the words picked; null for "None of these". */
  async function answer(chosen: string | null) {
    setBusy(chosen === null ? "deny" : "approve");
    setError(null);
    try {
      const approval = chosen !== null ? { publicKey: request.publicKey, challenge: request.challenge, phrase: chosen } : undefined;
      const result = await callPopup("signInRequests:answer", { id: request.id, approve: chosen !== null, ...(approval ? { approval } : {}) });
      if (result.outcome === "done" && chosen !== null && result.code) return signIns.answered(request.id, { kind: "code", code: result.code });
      if (result.outcome === "mismatch") return signIns.answered(request.id, { kind: "mismatch" });
      signIns.answered(request.id);
      if (result.outcome === "done") ctx.notify(chosen === null ? "Sign-in request denied." : "Sign-in approved.");
      else ctx.notify(OUTCOME_NOTE[result.outcome]);
    } catch (e) {
      if (codeOf(e) === CHANGED_CODE) return signIns.changed(request.id);
      setError(msg(e));
      setBusy(null);
    }
  }

  return (
    <Modal title="Sign-in request" subtitle={`Asked at ${requestTime(request.createdAt)}`} icon="shield" onClose={close}>
      <p className="card-text">
        A device is asking to sign in to <strong className="wrap-anywhere">{ctx.state.email}</strong>.
      </p>
      <dl className="claims">
        <div>
          <dt>Device (as it calls itself)</dt>
          <dd>{claimedText(request.deviceName) || "No name given"}</dd>
        </div>
        <div>
          <dt>App</dt>
          <dd>{appOf(request)}</dd>
        </div>
        {request.ip && (
          <div>
            <dt>Address</dt>
            <dd>{claimedText(request.ip)}</dd>
          </div>
        )}
      </dl>
      {request.choices.length > 0 ? (
        <fieldset className="choice-group">
          <legend className="field-label">Which words does the new device show?</legend>
          <div className="choices choices-plain">
            {request.choices.map((choice) => (
              <button key={choice} type="button" className="choice phrase-choice" disabled={!armed || busy !== null} onClick={() => void answer(choice)}>
                <PhraseChoiceWords phrase={choice} />
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
        Choosing the words the new device shows approves the sign-in: with the code you'll see next, it can open your vault without your master password. If you didn't ask to sign in, or it shows
        other words, choose None of these.
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
            <button type="button" className="btn btn-text btn-danger" disabled={busy !== null} onClick={() => void answer(null)}>
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

/** A request's sheet closed (it changed under it, or the words picked weren't its own): nothing else comes up until this is read. */
export function ClosedNote({ notice, onDone }: { notice: Exclude<ApprovalNotice, { kind: "code" }>; onDone: () => void }) {
  const denied = notice.kind === "mismatch";
  return (
    <Modal title={denied ? "Sign-in request denied" : "Sign-in request closed"} icon="shield" tone="danger" onClose={onDone}>
      <p className="card-text">{denied ? WORDS_MISMATCH : REQUEST_CHANGED}</p>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" onClick={onDone} data-autofocus="">
          OK
        </button>
      </SheetActions>
    </Modal>
  );
}

/**
 * After approving: the code to enter on the new device, kept on screen until Done (no Close; Escape doesn't dismiss
 * it: the new device can't finish without it). Done takes a press only a second after it appeared, so a key press
 * still on its way from picking the words can't dismiss it.
 */
export function CodeNote({ code, onDone }: { code: string; onDone: () => void }) {
  const armed = useArmed(ARM_DELAY_MS);
  return (
    <Modal title="Sign-in approved" icon="shield" closable={false} onClose={() => {}}>
      <p className="card-text">Enter this code on the new device:</p>
      <p className="approval-code">{groupedCode(code)}</p>
      <p className="small muted">The new device can open your vault only with this code. Never read it out or give it to anyone.</p>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" disabled={!armed} onClick={onDone}>
          Done
        </button>
      </SheetActions>
    </Modal>
  );
}
