import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { ConfirmDialog, copySecret, ErrorText, Icon, Modal, PasswordInput, SheetActions, toast } from "../components/ui";
import { friendlyError, hasFeature, usePublicConfig } from "../lib/api";
import { createSend, deleteSend, getSend, linkOf, listSends, nameOf, textOf, updateSend, type SendEdit } from "../lib/send-client";
import {
  SEND_NAME_MAX,
  SEND_STATE_LABEL,
  defaultDeletion,
  durationChoices,
  maskedSendLink,
  maxTextBytes,
  sendLimits,
  sendState,
  utf8Length,
  viewsText,
  type OwnedSend,
} from "../lib/sends";
import { formatBytes } from "../lib/sizes";
import "../styles/files.css";

const nowSeconds = () => Math.floor(Date.now() / 1000);
const formatWhen = (seconds: number) => new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
/** Most views a Send may allow (the server's limit). */
const MAX_VIEWS = 1_000_000;

/** Text shared through an encrypted link: the owner's list, with new, edit, copy link, turn off and delete. */
export function SendsPage() {
  const config = usePublicConfig();
  const enabled = hasFeature(config, "sends");
  const limits = sendLimits(config?.limits);
  const [sends, setSends] = useState<OwnedSend[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<OwnedSend | "new" | null>(null);
  const [created, setCreated] = useState<{ link: string; name: string; send: OwnedSend } | null>(null);
  const [deleting, setDeleting] = useState<OwnedSend | null>(null);

  const load = useCallback(async () => {
    try {
      setSends(await listSends());
      setError(null);
    } catch (e) {
      setError(`Couldn't load your Sends. ${friendlyError(e)}`);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Names are decrypted once per Send (their key is unwrapped with the account key).
  const names = useMemo(() => new Map((sends ?? []).map((s) => [s.id, nameOf(s)])), [sends]);

  async function toggle(s: OwnedSend) {
    try {
      await updateSend(s, { disabled: !s.disabled });
      toast(s.disabled ? "Link turned on" : "Link turned off");
      await load();
    } catch (e) {
      toast(friendlyError(e));
    }
  }

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <div className="row-between">
            <h1>Send</h1>
            {enabled && (
              <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
                <Icon name="plus" /> New Send
              </button>
            )}
          </div>
          <p>
            Share a password or a note through a link that works for anyone, even without PassAuth. The text is encrypted on this device and the key is only in
            the link, so your server can't read it.
          </p>
        </header>

        {config && !enabled && (
          <div className="alert alert-info" role="note">
            Send is turned off on this server, so links you made don't open now. Ask the server's admin if you need it.
          </div>
        )}
        <ErrorText error={error} />

        {sends === null && !error && (
          <p className="muted" role="status">
            Loading…
          </p>
        )}
        {sends?.length === 0 && (
          <div className="card empty">
            <span className="tile" aria-hidden="true">
              <Icon name="send" size={22} />
            </span>
            <p className="empty-title">No Sends yet</p>
            <p>Each Send is deleted on the date you choose, and can stop working sooner: after a number of views, or at an expiry date.</p>
          </div>
        )}
        {sends && sends.length > 0 && (
          <ul className="send-list" aria-label="Your Sends">
            {sends.map((s) => (
              <SendRow
                key={s.id}
                send={s}
                name={names.get(s.id) ?? null}
                enabled={enabled}
                onEdit={() => setEditing(s)}
                onToggle={() => toggle(s)}
                onDelete={() => setDeleting(s)}
              />
            ))}
          </ul>
        )}
      </div>

      {editing && (
        <SendEditor
          send={editing === "new" ? null : editing}
          maxDays={limits.maxDays}
          maxBytes={limits.maxBytes}
          onClose={() => setEditing(null)}
          onSaved={async (result) => {
            setEditing(null);
            if (result) setCreated(result);
            else toast("Send saved");
            await load();
          }}
        />
      )}
      {created && <SendCreated {...created} onClose={() => setCreated(null)} />}
      {deleting && (
        <ConfirmDialog
          title="Delete this Send?"
          subtitle={names.get(deleting.id) ?? "Send"}
          icon="send"
          action="Delete Send"
          busyAction="Deleting…"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await deleteSend(deleting.id);
            setDeleting(null);
            toast("Send deleted");
            await load();
          }}
        >
          <p className="card-text">Its link stops working at once, for everyone who has it.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function SendRow({
  send: s,
  name,
  enabled,
  onEdit,
  onToggle,
  onDelete,
}: {
  send: OwnedSend;
  name: string | null;
  enabled: boolean;
  onEdit: () => void;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const now = nowSeconds();
  const state = sendState(s, now);
  const facts = [
    viewsText(s),
    s.expiresAt !== null && (s.expiresAt > now ? `Link expires ${formatWhen(s.expiresAt)}` : `Link expired ${formatWhen(s.expiresAt)}`),
    `Kept until ${formatWhen(s.deleteAt)}`,
    s.hasPassword && "Password",
    s.hideEmail && "Your email hidden",
  ].filter((f): f is string => typeof f === "string");
  const readable = name !== null;
  return (
    <li className="send-row">
      <div className="send-row-head">
        <span className="tile" aria-hidden="true">
          <Icon name="send" />
        </span>
        <div className="grow">
          <span className="row-title">{name ?? "Send that can't be opened"}</span>
          <ul className="send-facts">
            {facts.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
        <span className={state === "available" ? "badge badge-ok" : "badge"}>{SEND_STATE_LABEL[state]}</span>
      </div>
      {!readable && <p className="small muted">This Send was made with keys your account no longer has. Delete it and make a new one.</p>}
      <div className="card-actions">
        {readable && (
          <button type="button" className="btn btn-sm" onClick={() => copySecret(linkOf(s), "Link")}>
            <Icon name="copy" size={16} /> Copy link
          </button>
        )}
        {readable && enabled && (
          <button type="button" className="btn btn-sm" onClick={onEdit}>
            <Icon name="edit" size={16} /> Edit
          </button>
        )}
        {enabled && (
          <button type="button" className="btn btn-sm btn-text" onClick={onToggle}>
            {s.disabled ? "Turn on link" : "Turn off link"}
          </button>
        )}
        <button type="button" className="btn btn-sm btn-text btn-danger" onClick={onDelete}>
          Delete…
        </button>
      </div>
    </li>
  );
}

// ------------------------------------------------------------------ editor

/** `YYYY-MM-DDTHH:mm` in local time, for a `datetime-local` input. */
function toLocalInput(seconds: number): string {
  const d = new Date(seconds * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
const fromLocalInput = (value: string): number => Math.floor(new Date(value).getTime() / 1000);

type PasswordMode = "none" | "keep" | "set" | "remove";

/** New Send, or changes to one (its text is fetched and decrypted when the editor opens). */
function SendEditor({
  send,
  maxDays,
  maxBytes,
  onClose,
  onSaved,
}: {
  send: OwnedSend | null;
  maxDays: number;
  maxBytes: number;
  onClose: () => void;
  onSaved: (created: { link: string; name: string; send: OwnedSend } | null) => Promise<void>;
}) {
  const isNew = send === null;
  const durations = durationChoices(maxDays);
  const [loaded, setLoaded] = useState<{ name: string; text: string } | null>(isNew ? { name: "", text: "" } : null);
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [passwordMode, setPasswordMode] = useState<PasswordMode>(send?.hasPassword ? "keep" : "none");
  const [password, setPassword] = useState("");
  const [views, setViews] = useState(send?.maxViews ? String(send.maxViews) : "");
  const [deletion, setDeletion] = useState(isNew ? String(defaultDeletion(maxDays)) : "keep");
  const [deletionAt, setDeletionAt] = useState(() => toLocalInput((send?.deleteAt ?? nowSeconds() + defaultDeletion(maxDays))));
  const [expiry, setExpiry] = useState(send?.expiresAt ? "keep" : "never");
  const [expiryAt, setExpiryAt] = useState(() => toLocalInput(send?.expiresAt ?? nowSeconds() + 86400));
  const [hideEmail, setHideEmail] = useState(send?.hideEmail ?? false);
  const [disabled, setDisabled] = useState(send?.disabled ?? false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!send) return;
    let live = true;
    getSend(send.id)
      .then((full) => {
        if (!live) return;
        const values = { name: nameOf(full) ?? "", text: textOf(full) };
        setLoaded(values);
        setName(values.name);
        setText(values.text);
      })
      .catch((e) => live && setError(`Couldn't open this Send. ${friendlyError(e)}`));
    return () => {
      live = false;
    };
  }, [send]);

  const textBytes = utf8Length(text);
  const maxText = maxTextBytes(maxBytes);
  const close = () => {
    if (!busy) onClose();
  };

  /** The deletion or expiry chosen, in Unix seconds (`keep` = the current one). NaN for a custom date that isn't one. */
  const pick = (choice: string, custom: string, current: number | null, now: number): number | null => {
    if (choice === "never") return null;
    if (choice === "keep") return current;
    if (choice === "custom") return fromLocalInput(custom);
    return now + Number(choice);
  };

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!loaded) return;
    setError(null);
    const now = nowSeconds();
    if (!name.trim()) return setError("Give this Send a name. People who open it see it too.");
    if (!text) return setError("Enter the text to send.");
    if (textBytes > maxText) return setError(`This text is too long. A Send holds up to ${formatBytes(maxText)} of text.`);
    let maxViews: number | null = null;
    if (views.trim()) {
      maxViews = Number(views);
      if (!Number.isInteger(maxViews) || maxViews < 1 || maxViews > MAX_VIEWS) return setError("Enter how many times it can be opened: a whole number from 1 to 1,000,000.");
    }
    const deleteAt = pick(deletion, deletionAt, send?.deleteAt ?? null, now);
    if (deleteAt === null || !Number.isFinite(deleteAt) || deleteAt <= now) return setError("Pick a deletion date in the future.");
    if (deletion !== "keep" && deleteAt > now + maxDays * 86400) return setError(`Pick a deletion date within ${maxDays} ${maxDays === 1 ? "day" : "days"}: your server keeps Sends no longer.`);
    const expiresAt = pick(expiry, expiryAt, send?.expiresAt ?? null, now);
    if (expiresAt !== null) {
      if (!Number.isFinite(expiresAt) || (expiry !== "keep" && expiresAt <= now)) return setError("Pick an expiry date in the future, or choose Never.");
      if (expiresAt >= deleteAt) return setError("The Send is deleted before it would expire. Pick an expiry date before the deletion date, or choose Never.");
    }
    if (passwordMode === "set" && !password) return setError("Enter the new password, or keep the current one.");
    setBusy(true);
    // The password's key derivation blocks the page for a moment: let "Saving…" paint first.
    await new Promise((r) => setTimeout(r, 30));
    try {
      if (isNew) {
        const name_ = name.trim();
        const r = await createSend({ name: name_, text, password: password || null, maxViews, expiresAt, deleteAt, hideEmail });
        await onSaved({ link: r.link, name: name_, send: r.send });
      } else {
        const edit: SendEdit = {};
        if (name.trim() !== loaded.name) edit.name = name.trim();
        if (text !== loaded.text) edit.text = text;
        if (passwordMode === "remove") edit.password = null;
        else if ((passwordMode === "set" || passwordMode === "none") && password) edit.password = password;
        if (maxViews !== send.maxViews) edit.maxViews = maxViews;
        if (expiresAt !== send.expiresAt) edit.expiresAt = expiresAt;
        if (deleteAt !== send.deleteAt) edit.deleteAt = deleteAt;
        if (disabled !== send.disabled) edit.disabled = disabled;
        if (hideEmail !== send.hideEmail) edit.hideEmail = hideEmail;
        await updateSend(send, edit);
        await onSaved(null);
      }
    } catch (err) {
      setError(friendlyError(err));
      setBusy(false);
    }
  }

  const durationOptions = durations.map(([seconds, label]) => (
    <option key={seconds} value={String(seconds)}>
      In {label}
    </option>
  ));

  return (
    <Modal title={isNew ? "New Send" : "Edit Send"} subtitle={isNew ? "Text shared through an encrypted link" : loaded?.name || undefined} icon="send" onClose={close}>
      {!loaded && !error && (
        <p className="muted small" role="status">
          Opening…
        </p>
      )}
      {loaded && (
        <form className="stack" onSubmit={submit}>
          <div className="field">
            <label htmlFor="send-name">Name</label>
            <input
              id="send-name"
              className="input"
              value={name}
              maxLength={SEND_NAME_MAX}
              onChange={(e) => setName(e.target.value)}
              autoComplete="off"
              aria-describedby="send-name-hint"
              required
            />
            <span className="field-hint" id="send-name-hint">
              Shown to the people who open it, after any password.
            </span>
          </div>
          <div className="field">
            <label htmlFor="send-text">Text</label>
            <textarea
              id="send-text"
              className="textarea send-input"
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              aria-describedby={textBytes > maxText * 0.8 ? "send-text-size" : undefined}
              required
            />
            {textBytes > maxText * 0.8 && (
              <span className={textBytes > maxText ? "field-hint field-error" : "field-hint"} id="send-text-size">
                {formatBytes(textBytes)} of {formatBytes(maxText)}
              </span>
            )}
          </div>

          {send?.hasPassword ? (
            <label className="field">
              <span>Password</span>
              <select className="select" value={passwordMode} onChange={(e) => setPasswordMode(e.target.value as PasswordMode)}>
                <option value="keep">Keep the current password</option>
                <option value="set">Set a new password</option>
                <option value="remove">Remove the password</option>
              </select>
            </label>
          ) : null}
          {(!send?.hasPassword || passwordMode === "set") && (
            <div className="field">
              <label htmlFor="send-password">{send?.hasPassword ? "New password" : "Password (optional)"}</label>
              <PasswordInput id="send-password" value={password} onChange={setPassword} autoComplete="new-password" />
              <span className="field-hint">People need it, as well as the link, to open the Send. Tell it to them another way than the link.</span>
            </div>
          )}

          <div className="field-pair">
            <label className="field">
              <span>Delete it</span>
              <select className="select" value={deletion} onChange={(e) => setDeletion(e.target.value)}>
                {!isNew && <option value="keep">{formatWhen(send.deleteAt)}</option>}
                {durationOptions}
                <option value="custom">On a date…</option>
              </select>
            </label>
            <label className="field">
              <span>Link expires</span>
              <select className="select" value={expiry} onChange={(e) => setExpiry(e.target.value)}>
                <option value="never">Never (when it's deleted)</option>
                {send?.expiresAt ? <option value="keep">{formatWhen(send.expiresAt)}</option> : null}
                {durationOptions}
                <option value="custom">On a date…</option>
              </select>
            </label>
          </div>
          {(deletion === "custom" || expiry === "custom") && (
            <div className="field-pair">
              {deletion === "custom" && (
                <label className="field">
                  <span>Deletion date</span>
                  <input
                    className="input"
                    type="datetime-local"
                    value={deletionAt}
                    min={toLocalInput(nowSeconds() + 60)}
                    max={toLocalInput(nowSeconds() + maxDays * 86400)}
                    onChange={(e) => setDeletionAt(e.target.value)}
                  />
                </label>
              )}
              {expiry === "custom" && (
                <label className="field">
                  <span>Expiry date</span>
                  <input className="input" type="datetime-local" value={expiryAt} min={toLocalInput(nowSeconds() + 60)} onChange={(e) => setExpiryAt(e.target.value)} />
                </label>
              )}
            </div>
          )}
          <span className="field-hint send-hint">
            Your server deletes Sends after {maxDays} {maxDays === 1 ? "day" : "days"} at most. An expired link stops working; the Send stays in this list until it's
            deleted.
          </span>

          <div className="field">
            <label htmlFor="send-views">Limit how many times it can be opened (optional)</label>
            <input
              id="send-views"
              className="input field-narrow"
              type="number"
              inputMode="numeric"
              min={1}
              max={MAX_VIEWS}
              step={1}
              value={views}
              onChange={(e) => setViews(e.target.value)}
              aria-describedby={send && send.views > 0 ? "send-views-hint" : undefined}
            />
            {send && send.views > 0 && (
              <span className="field-hint" id="send-views-hint">
                {viewsText({ views: send.views, maxViews: null })} so far.
              </span>
            )}
          </div>

          <label className="check">
            <input type="checkbox" checked={hideEmail} onChange={(e) => setHideEmail(e.target.checked)} />
            <span>Hide my email address from the people who open it</span>
          </label>
          {!isNew && (
            <label className="check">
              <input type="checkbox" checked={disabled} onChange={(e) => setDisabled(e.target.checked)} />
              <span>Turn off the link: nobody can open it until you turn it on again</span>
            </label>
          )}

          <ErrorText error={error} />
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={close} disabled={busy}>
                Cancel
              </button>
            }
          >
            <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
              {busy ? "Saving…" : isNew ? "Create Send" : "Save changes"}
            </button>
          </SheetActions>
        </form>
      )}
      {!loaded && error && (
        <>
          <ErrorText error={error} />
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={close}>
                Close
              </button>
            }
          />
        </>
      )}
    </Modal>
  );
}

/**
 * Shown once after creating a Send: its link to copy. The key part (after #) is hidden until "Show link", so a screen
 * recording or someone looking along doesn't get it; Copy link always copies the whole link.
 */
function SendCreated({ link, name, send, onClose }: { link: string; name: string; send: OwnedSend; onClose: () => void }) {
  const [shown, setShown] = useState(false);
  return (
    <Modal title="Send created" subtitle={name} icon="send" onClose={onClose}>
      <div className="field">
        <label htmlFor="send-link">Link</label>
        <div className="input-group">
          <input
            id="send-link"
            className="input mono send-link"
            value={shown ? link : maskedSendLink(link)}
            readOnly
            onFocus={(e) => shown && e.currentTarget.select()}
            aria-describedby="send-link-hint"
          />
          <button type="button" className="btn btn-icon" aria-label={shown ? "Hide link" : "Show link"} aria-pressed={shown} onClick={() => setShown(!shown)}>
            <Icon name={shown ? "eyeOff" : "eye"} />
          </button>
        </div>
        <span className="field-hint" id="send-link-hint">
          Anyone with this link{send.hasPassword ? " and the password" : ""} can open it until {formatWhen(send.expiresAt ?? send.deleteAt)}
          {send.maxViews ? `, at most ${send.maxViews === 1 ? "once" : `${send.maxViews} times`}` : ""}. The part after # is the key, so it's hidden here;
          Copy link copies the whole link. Share it only with the people it's for. You can copy it again from this list.
        </span>
      </div>
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={onClose}>
            Done
          </button>
        }
      >
        <button type="button" className="btn btn-primary btn-block" onClick={() => copySecret(link, "Link")} data-autofocus="">
          <Icon name="copy" /> Copy link
        </button>
      </SheetActions>
    </Modal>
  );
}
