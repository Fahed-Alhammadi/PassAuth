import { useCallback, useDeferredValue, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { ReadOnlyFiles } from "../components/Attachments";
import { ConfirmDialog, ErrorText, Icon, Modal, SheetActions, SiteIcon, toast } from "../components/ui";
import { friendlyError, hasFeature, usePublicConfig } from "../lib/api";
import { readAttachments } from "../lib/attachments";
import {
  DEFAULT_WAIT_DAYS,
  MAX_WAIT_DAYS,
  MIN_WAIT_DAYS,
  daysText,
  grantorActions,
  grantorStatus,
  granteeActions,
  granteeStatus,
  personName,
  validWait,
  type Grant,
} from "../lib/emergency";
import {
  acceptGrant,
  approveGrant,
  changeWait,
  confirmContact,
  inviteContact,
  listGrants,
  openGrantorVault,
  rejectGrant,
  removeGrant,
  requestAccess,
  type GrantorEntry,
  type GrantorVault,
} from "../lib/emergency-client";
import { emergencyAttachmentPath } from "../lib/files";
import { KIND_LABEL, kindOf } from "../lib/types";
import { fingerprint } from "../lib/vault";
import { ItemFields } from "./Vault";
import "../styles/files.css";

const formatWhen = (seconds: number) => new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/**
 * What confirming a contact means, said before it is done: the contact gets the account key itself, which also opens
 * shared vaults and Sends, and nothing can take it back.
 */
const fullTrust = (who: string) =>
  `Confirming gives ${who} your account key for good. Once they get access (or at once, if your server is ever compromised) they can read everything in your account, shared vaults included, and removing them later can't take that back. Only add someone you trust completely.`;

function safeFingerprint(publicKey: string): string | null {
  if (typeof publicKey !== "string" || !publicKey) return null;
  try {
    return fingerprint(publicKey);
  } catch {
    return null;
  }
}

type Lists = { asGrantor: Grant[]; asGrantee: Grant[] };

/** Settings → Emergency access (`/settings/emergency`, where the server's emails link). */
export function EmergencyTab() {
  const enabled = hasFeature(usePublicConfig(), "emergency_access");
  const [lists, setLists] = useState<Lists | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLists(await listGrants());
      setError(null);
    } catch (e) {
      setError(`Couldn't load your emergency contacts. ${friendlyError(e)}`);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <section className="card" aria-labelledby="ea-title">
        <h2 id="ea-title">Emergency access</h2>
        <p className="card-text">
          Name someone you trust who can ask to view your own vaults if you can't, say after an accident. You're told at once and have the waiting period to
          say no. After that they can view your vaults, not the ones you share, and can't change anything.
        </p>
        <p className="small muted">
          The waiting period is a rule of your server, not of the encryption. Once someone has had access, they keep what they saw: if you stop trusting them,
          end their access and change the passwords that matter.
        </p>
      </section>
      {!enabled && (
        <div className="alert alert-info" role="note">
          Emergency access is turned off on this server: nobody can be named, accept or ask for access while it's off. Ask the server's admin if you need it.
        </div>
      )}
      <ErrorText error={error} />

      <section className="card" aria-labelledby="ea-contacts">
        <h2 id="ea-contacts">Your trusted contacts</h2>
        {lists && lists.asGrantor.length === 0 && <p className="card-text">You haven't named anyone yet.</p>}
        {lists?.asGrantor.map((g) => (
          <ContactRow key={g.id} grant={g} reload={load} />
        ))}
        {enabled && <AddContact onAdded={load} />}
      </section>

      <section className="card" aria-labelledby="ea-trusting">
        <h2 id="ea-trusting">People who trust you</h2>
        {lists && lists.asGrantee.length === 0 && <p className="card-text">Nobody has named you as their emergency contact.</p>}
        {lists?.asGrantee.map((g) => (
          <TrustingRow key={g.id} grant={g} enabled={enabled} reload={load} />
        ))}
      </section>
      {!lists && !error && (
        <p className="muted" role="status">
          Loading…
        </p>
      )}
    </>
  );
}

function AddContact({ onAdded }: { onAdded: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [days, setDays] = useState(String(DEFAULT_WAIT_DAYS));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const wait = Number(days);
    if (!email.trim()) return setError("Enter your contact's email address.");
    if (!validWait(wait)) return setError(`Choose a waiting period from ${MIN_WAIT_DAYS} to ${MAX_WAIT_DAYS} days.`);
    setBusy(true);
    setError(null);
    try {
      const g = await inviteContact(email, wait);
      setEmail("");
      toast(`${personName(g.grantee)} was asked to be your emergency contact`);
      await onAdded();
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="stack-s ea-add" onSubmit={submit}>
      <h3 className="section-title">Add a trusted contact</h3>
      <div className="inline-form">
        <label className="field">
          <span>Their email address</span>
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" spellCheck={false} />
        </label>
        <label className="field ea-days">
          <span>Waiting period (days)</span>
          <input className="input" type="number" inputMode="numeric" min={MIN_WAIT_DAYS} max={MAX_WAIT_DAYS} step={1} value={days} onChange={(e) => setDays(e.target.value)} />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Adding…" : "Add contact"}
        </button>
      </div>
      <span className="field-hint">They need an account on this server. They accept, then you confirm them by checking their fingerprint together.</span>
      <p className="small muted">{fullTrust("a contact")}</p>
      <ErrorText error={error} />
    </form>
  );
}

/** A grant's row: who, what it means now, and what can be done. */
function GrantRow({ grant: g, who, status, children }: { grant: Grant; who: string; status: { label: string; text: string; tone: string }; children?: ReactNode }) {
  const titleId = `grant-${g.id}`;
  return (
    <div className="person" role="group" aria-labelledby={titleId}>
      <div className="sheet-context">
        <span className="tile" aria-hidden="true">
          <Icon name="lifebuoy" />
        </span>
        <div className="grow">
          <div className="row-title" id={titleId}>
            {who}
          </div>
          <div className="row-sub">Waiting period: {daysText(g.waitDays)}</div>
        </div>
        <span className={status.tone === "ok" ? "badge badge-ok" : status.tone === "warn" ? "badge badge-attn" : "badge"}>{status.label}</span>
      </div>
      <p className="card-text">{status.text}</p>
      {children}
    </div>
  );
}

/** Someone the account named (the account is the grantor). */
function ContactRow({ grant: g, reload }: { grant: Grant; reload: () => Promise<void> }) {
  const [asking, setAsking] = useState<"confirm" | "approve" | "end" | "remove" | "wait" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const who = personName(g.grantee);
  const email = g.grantee.name.trim() ? g.grantee.email : null;
  const actions = grantorActions(g);
  const fp = safeFingerprint(g.grantee.publicKey);

  const run = async (fn: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      toast(done);
      await reload();
    } catch (e) {
      setError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <GrantRow grant={g} who={email ? `${who} (${email})` : who} status={grantorStatus(g, formatWhen)}>
      <div className="card-actions">
        {actions.includes("confirm") && (
          <button type="button" className="btn btn-primary" onClick={() => setAsking("confirm")}>
            Check and confirm…
          </button>
        )}
        {actions.includes("approve") && (
          <button type="button" className="btn" onClick={() => setAsking("approve")} disabled={busy}>
            Approve now…
          </button>
        )}
        {actions.includes("reject") && (
          <button type="button" className="btn btn-primary" onClick={() => run(() => rejectGrant(g.id), "Request rejected")} disabled={busy}>
            Reject request
          </button>
        )}
        {actions.includes("end") && (
          <button type="button" className="btn btn-danger" onClick={() => setAsking("end")}>
            End access…
          </button>
        )}
        {actions.includes("wait") && (
          <button type="button" className="btn btn-text" onClick={() => setAsking("wait")}>
            Change waiting period
          </button>
        )}
        {actions.includes("remove") && (
          <button type="button" className="btn btn-text btn-danger" onClick={() => setAsking("remove")}>
            Remove…
          </button>
        )}
      </div>
      <ErrorText error={error} />

      {asking === "confirm" && (
        <ConfirmDialog
          title={`Confirm ${who}?`}
          subtitle={g.grantee.email}
          icon="lifebuoy"
          danger={false}
          action="Confirm contact"
          busyAction="Confirming…"
          // Without a fingerprint their account can't be checked, so it can't be confirmed either.
          disabled={!fp}
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await confirmContact(g);
            setAsking(null);
            toast(`${who} is your emergency contact now`);
            await reload();
          }}
        >
          <p className="card-text">
            Confirming lets {who} ask for access later: your vaults' key is locked so that only their account can open it. First make sure it's really their
            account.
          </p>
          <div className="alert alert-warn small" role="note">
            {fullTrust(who)}
          </div>
          {fp ? (
            <div className="field">
              <span>{who}'s key fingerprint</span>
              <div className="fingerprint">{fp}</div>
              <span className="field-hint">
                Ask {who} to open Settings, then Account, and read you their fingerprint, in person or on a call. Confirm only if it matches exactly.
              </span>
            </div>
          ) : (
            <div className="alert alert-error small" role="note">
              PassAuth can't show {who}'s fingerprint, so their account can't be checked and they can't be confirmed. Remove them, then add them again.
            </div>
          )}
        </ConfirmDialog>
      )}
      {asking === "approve" && (
        <ConfirmDialog
          title={`Give ${who} access now?`}
          subtitle={g.grantee.email}
          icon="lifebuoy"
          danger={false}
          action="Approve access"
          busyAction="Approving…"
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await approveGrant(g.id);
            setAsking(null);
            toast(`${who} can view your vaults now`);
            await reload();
          }}
        >
          <p className="card-text">
            {who} can view your own vaults at once, without waiting. They keep what they see, even if you end their access later.
          </p>
        </ConfirmDialog>
      )}
      {asking === "end" && (
        <ConfirmDialog
          title={`End ${who}'s access?`}
          subtitle={g.grantee.email}
          icon="lifebuoy"
          action="End access"
          busyAction="Ending…"
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await rejectGrant(g.id);
            setAsking(null);
            toast("Access ended");
            await reload();
          }}
        >
          <p className="card-text">
            {who} can't view your vaults any more, but keeps whatever they already saw. If you no longer trust them, change the passwords that matter. They can
            ask for access again.
          </p>
        </ConfirmDialog>
      )}
      {asking === "remove" && (
        <ConfirmDialog
          title={`Remove ${who}?`}
          subtitle="Emergency contact"
          icon="lifebuoy"
          action="Remove contact"
          busyAction="Removing…"
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await removeGrant(g.id);
            setAsking(null);
            toast("Emergency contact removed");
            await reload();
          }}
        >
          <p className="card-text">
            {who} can't ask for access any more.
            {(g.status === "approved" || g.status === "rejected" || g.status === "requested") &&
              " If they ever had access, they keep what they saw: change the passwords that matter if you no longer trust them."}
          </p>
        </ConfirmDialog>
      )}
      {asking === "wait" && (
        <WaitDialog
          grant={g}
          who={who}
          onClose={() => setAsking(null)}
          onSaved={async () => {
            setAsking(null);
            toast("Waiting period changed");
            await reload();
          }}
        />
      )}
    </GrantRow>
  );
}

function WaitDialog({ grant: g, who, onClose, onSaved }: { grant: Grant; who: string; onClose: () => void; onSaved: () => Promise<void> }) {
  const [days, setDays] = useState(String(g.waitDays));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => {
    if (!busy) onClose();
  };

  async function submit(e: FormEvent) {
    e.preventDefault();
    const wait = Number(days);
    if (!validWait(wait)) return setError(`Choose a waiting period from ${MIN_WAIT_DAYS} to ${MAX_WAIT_DAYS} days.`);
    setBusy(true);
    setError(null);
    try {
      await changeWait(g.id, wait);
      await onSaved();
    } catch (err) {
      setError(friendlyError(err));
      setBusy(false);
    }
  }

  return (
    <Modal title="Change the waiting period" subtitle={who} icon="lifebuoy" onClose={close}>
      <form className="stack" onSubmit={submit}>
        <div className="field">
          <label htmlFor="ea-wait">Days to say no after {who} asks</label>
          <input
            id="ea-wait"
            className="input field-narrow"
            type="number"
            inputMode="numeric"
            min={MIN_WAIT_DAYS}
            max={MAX_WAIT_DAYS}
            step={1}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            aria-describedby="ea-wait-hint"
          />
          <span className="field-hint" id="ea-wait-hint">
            From {MIN_WAIT_DAYS} to {MAX_WAIT_DAYS} days.{g.status === "requested" && " A request already waiting follows the new period, counted from when they asked."}
          </span>
        </div>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={close} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

/** Someone who named the account (the account is the contact). */
function TrustingRow({ grant: g, enabled, reload }: { grant: Grant; enabled: boolean; reload: () => Promise<void> }) {
  const [asking, setAsking] = useState<"decline" | "request" | "remove" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const who = personName(g.grantor);
  const email = g.grantor.name.trim() ? g.grantor.email : null;
  const actions = granteeActions(g);

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      await acceptGrant(g.id);
      toast(`Accepted. ${who} confirms you next.`);
      await reload();
    } catch (e) {
      setError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <GrantRow grant={g} who={email ? `${who} (${email})` : who} status={granteeStatus(g, formatWhen)}>
      <div className="card-actions">
        {enabled && actions.includes("accept") && (
          <button type="button" className="btn btn-primary" onClick={accept} disabled={busy}>
            {busy ? "Accepting…" : "Accept"}
          </button>
        )}
        {actions.includes("decline") && (
          <button type="button" className="btn btn-text btn-danger" onClick={() => setAsking("decline")}>
            Decline…
          </button>
        )}
        {enabled && actions.includes("request") && (
          <button type="button" className="btn" onClick={() => setAsking("request")}>
            Ask for access…
          </button>
        )}
        {enabled && actions.includes("view") && (
          <Link className="btn btn-primary" to={`/emergency/${encodeURIComponent(g.id)}`}>
            View {who}'s vaults
          </Link>
        )}
        {actions.includes("remove") && (
          <button type="button" className="btn btn-text btn-danger" onClick={() => setAsking("remove")}>
            Stop being their contact…
          </button>
        )}
      </div>
      <ErrorText error={error} />

      {asking === "request" && (
        <ConfirmDialog
          title={`Ask for access to ${who}'s vaults?`}
          subtitle={g.grantor.email}
          icon="lifebuoy"
          danger={false}
          action="Ask for access"
          busyAction="Asking…"
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await requestAccess(g.id);
            setAsking(null);
            toast(`${who} was told about your request`);
            await reload();
          }}
        >
          <p className="card-text">
            {who} is emailed at once. Unless they reject it, you can view their own vaults in {daysText(g.waitDays)}. Ask only if they really can't reach their
            vaults themselves.
          </p>
        </ConfirmDialog>
      )}
      {(asking === "decline" || asking === "remove") && (
        <ConfirmDialog
          title={asking === "decline" ? `Decline ${who}'s invitation?` : `Stop being ${who}'s emergency contact?`}
          subtitle={g.grantor.email}
          icon="lifebuoy"
          action={asking === "decline" ? "Decline" : "Stop being their contact"}
          busyAction="Removing…"
          onClose={() => setAsking(null)}
          onConfirm={async () => {
            await removeGrant(g.id);
            setAsking(null);
            toast(asking === "decline" ? "Invitation declined" : "You're no longer their emergency contact");
            await reload();
          }}
        >
          <p className="card-text">You won't be able to ask for access to {who}'s vaults. They can name you again.</p>
        </ConfirmDialog>
      )}
    </GrantRow>
  );
}

// ------------------------------------------------------------- the vault

/**
 * A grantor's own vaults, read-only, through an approved emergency access (`/emergency/<access id>`). Decrypted into
 * this page's memory only: nothing is stored, and it is gone when the page closes or the vault locks.
 */
export function EmergencyVaultPage() {
  const { id = "" } = useParams();
  const [view, setView] = useState<GrantorVault | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const deferred = useDeferredValue(query);
  const [showTrash, setShowTrash] = useState(false);
  const [opened, setOpened] = useState<GrantorEntry | null>(null);

  useEffect(() => {
    let live = true;
    openGrantorVault(id).then(
      (v) => live && setView(v),
      (e) => live && setError(friendlyError(e)),
    );
    return () => {
      live = false;
    };
  }, [id]);

  const trashed = view?.items.filter((e) => e.deletedAt !== null).length ?? 0;
  const list = useMemo(() => {
    if (!view) return [];
    const q = deferred.trim().toLowerCase();
    return view.items.filter(
      (e) =>
        (showTrash || e.deletedAt === null) &&
        (!q || e.item.name.toLowerCase().includes(q) || e.item.login?.username.toLowerCase().includes(q) || e.item.login?.urls.some((u) => u.url.toLowerCase().includes(q))),
    );
  }, [view, deferred, showTrash]);
  const vaultName = (vaultId: string) => view?.vaults.find((v) => v.id === vaultId)?.name ?? "Vault";
  const who = view ? personName(view.grant.grantor) : "";

  return (
    <div className="page">
      <div className="page-inner">
        <Link className="btn btn-text ea-back" to="/settings/emergency">
          <Icon name="back" /> Emergency access
        </Link>
        <header className="page-head">
          <h1>{view ? `${who}'s vaults` : "Emergency access"}</h1>
          <p>View only. Nothing of it is saved on this device: it's gone when you leave this page or PassAuth locks.</p>
        </header>
        <ErrorText error={error} />
        {!view && !error && (
          <p className="muted" role="status">
            Opening…
          </p>
        )}
        {view && (
          <>
            {view.failed > 0 && (
              <div className="alert alert-warn small" role="note">
                {view.failed === 1 ? "One item couldn't be opened and is" : `${view.failed} items couldn't be opened and are`} left out.
              </div>
            )}
            <div className="input-group">
              <span className="input-lead">
                <Icon name="search" />
              </span>
              <input className="input" type="search" placeholder="Search" aria-label={`Search ${who}'s items`} value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            {trashed > 0 && (
              <label className="check">
                <input type="checkbox" checked={showTrash} onChange={(e) => setShowTrash(e.target.checked)} />
                <span>Show items in the trash ({trashed})</span>
              </label>
            )}
            {list.length === 0 ? (
              <div className="card empty">
                <p className="empty-title">{query ? `No items match "${query}"` : "No items"}</p>
              </div>
            ) : (
              <div className="choices ea-items">
                {list.map((e) => (
                  <button key={e.id} type="button" className="choice" onClick={() => setOpened(e)}>
                    <SiteIcon host="" name={e.item.name} enabled={false} />
                    <span className="choice-text">
                      <span className="choice-title">{e.item.name || "Untitled"}</span>
                      <span className="choice-sub">
                        {KIND_LABEL[kindOf(e.item)]}
                        {view.vaults.length > 1 && `, ${vaultName(e.vaultId)}`}
                        {e.deletedAt !== null && ", in the trash"}
                      </span>
                    </span>
                    <span className="choice-trail" aria-hidden="true">
                      <Icon name="chevron" size={16} />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
      {opened && view && (
        <Modal
          title={opened.item.name || "Untitled"}
          subtitle={`${KIND_LABEL[kindOf(opened.item)]} in ${vaultName(opened.vaultId)}, view only`}
          icon={<SiteIcon host="" name={opened.item.name} enabled={false} />}
          onClose={() => setOpened(null)}
        >
          <div className="stack ea-item">
            <ItemFields item={opened.item} />
            <ReadOnlyFiles itemId={opened.id} files={readAttachments(opened.item)} path={(attachment) => emergencyAttachmentPath(view.grant.id, attachment)} />
          </div>
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={() => setOpened(null)}>
                Close
              </button>
            }
          />
        </Modal>
      )}
    </div>
  );
}
