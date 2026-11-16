/**
 * Signed sharing in the web vault and desktop app (docs/ARCHITECTURE.md "Signed sharing"): how a vault's key and
 * people's identities are vouched for, the "Mark as verified" / "Trust the new key" check against an identity
 * fingerprint, the member review before a vault's members are signed, and the notices for vaults that failed their check.
 *
 * Display rule: a known person is called by the email pinned for them; an email the server lists now only appears as
 * "listed by your server as …", and "Verified" never sits next to a name or email only the server vouches for.
 */
import { useState } from "react";
import { Link } from "react-router";
import { FIRST_SIGNED, NOT_YET_SIGNED, cleanText, emailConflictText, listedAs, signedByText, type PublicIdentity } from "../lib/signing";
import { emailText, type KeyChange, type ReviewView, type SignerView, type VaultTrust } from "../lib/signed-sharing";
import { personState, trustPerson, useVault, type Confirmation } from "../lib/vault";
import { ConfirmDialog, Icon, toast } from "./ui";

/** "Signed by <pinned email, else the signer's>". */
export const signerText = (s: SignerView) => signedByText(s.label, { name: "", email: s.label }, s.deleted);

/** A vault's signing state as a short label: "Not yet signed", "Signed by …"; nothing for the account's own vaults. */
export function trustLabel(trust: VaultTrust | undefined): string | null {
  if (!trust || trust.kind === "own") return null;
  if (trust.kind === "unsigned") return NOT_YET_SIGNED;
  return trust.signer ? signerText(trust.signer) : "Signed";
}

/** The label as a badge (warning colours for "Not yet signed"). */
export function TrustBadge({ trust }: { trust: VaultTrust | undefined }) {
  const label = trustLabel(trust);
  if (!label) return null;
  return (
    <span className={`badge${trust?.kind === "unsigned" ? " badge-attn" : ""}`} title={trust?.kind === "unsigned" ? "Shared before signed sharing" : undefined}>
      {label}
    </span>
  );
}

/** A pin state as a badge: Verified (only for a pinned identity), Not verified, New, Keys changed. */
export function PinBadge({ pin, verified }: { pin: string; verified: boolean }) {
  if (pin === "changed") return <span className="badge badge-warn">Keys changed</span>;
  if (pin === "email_conflict") return <span className="badge badge-warn">Another account uses this email</span>;
  if (pin === "match" && verified) return <span className="badge badge-ok">Verified</span>;
  if (pin === "new" || pin === "upgraded") return <span className="badge">New, not verified</span>;
  return <span className="badge">Not verified</span>;
}

/** "A different account uses <email>…": an email already pinned for another account (review L-C). */
export const conflictText = emailConflictText;

/**
 * Compare someone's identity fingerprint out of band, then pin exactly that identity (`hash`) as verified, with the
 * email this dialog shows (`label`). `changed`: their keys changed since they were pinned, and confirming trusts the new
 * ones. `conflict`: a different account uses an email pinned for another one: its own wording, and an explicit "I
 * compared it" tick before it can be trusted.
 */
export function VerifyDialog({
  identity,
  label,
  fingerprint,
  hash,
  changed,
  conflict = false,
  onClose,
}: {
  identity: PublicIdentity;
  /** What to call them (the pinned email, else the listed one; cleaned): pinned as shown. */
  label: string;
  fingerprint: string;
  hash: string;
  changed: boolean;
  conflict?: boolean;
  onClose: () => void;
}) {
  const who = cleanText(label) || "them";
  const [compared, setCompared] = useState(false);
  return (
    <ConfirmDialog
      title={conflict ? `Trust the new account for ${who}?` : changed ? `Trust ${who}'s new keys?` : `Verify ${who}?`}
      subtitle={conflict ? "A different account uses this email" : changed ? "Their keys changed" : "Compare their fingerprint"}
      icon="shield"
      danger={changed || conflict}
      action={conflict ? "Trust the new account" : changed ? "Trust the new key" : "Mark as verified"}
      busyAction="Saving…"
      disabled={conflict && !compared}
      onConfirm={async () => {
        // Pinned with the email this dialog shows (never "them", never one the server lists later).
        await trustPerson(identity, cleanText(label), { mode: changed || conflict ? "trust" : "verify", shownHash: hash });
        toast(changed || conflict ? `${who}'s new key is trusted` : `${who} is verified`);
      }}
      onClose={onClose}
    >
      {conflict ? (
        <p className="card-text">{conflictText(who)} A server trying to read shared vaults could also do this.</p>
      ) : (
        changed && (
          <p className="card-text">
            {who}'s keys aren't the ones PassAuth saw before. This happens when someone's account was set up again, but also when a server is trying to read
            shared vaults. Continue only after you compared the fingerprint with them.
          </p>
        )
      )}
      <div className="field">
        <span>{who}'s identity fingerprint</span>
        <div className="fingerprint">{fingerprint}</div>
        <span className="field-hint">
          Ask {who} to open Settings, then Account, and read you their identity fingerprint, in person or on a call. Confirm only if it matches exactly.
        </span>
      </div>
      {conflict && (
        <label className="check">
          <input type="checkbox" checked={compared} onChange={(e) => setCompared(e.target.checked)} />
          <span>I compared it with {who}, and it matches</span>
        </label>
      )}
    </ConfirmDialog>
  );
}

/** What to call someone: the pinned email first, else the server's name or email; and "listed by your server as …". */
export function personLabel(pinnedEmail: string | null, listedEmail: string, listedName: string): { title: string; sub: string | null } {
  const pinned = emailText(pinnedEmail);
  const email = emailText(listedEmail);
  const name = cleanText(listedName);
  if (pinned) return { title: pinned, sub: listedAs(pinned, email) };
  return { title: name || email || "Someone on this server", sub: name && email ? email : null };
}

/**
 * Someone's identity as this account knows it: the fingerprint, whether it was verified, and the action to verify it
 * (or to trust new keys). For member lists and the share sheet.
 */
export function PersonTrust({ identity, email, compact = false }: { identity: PublicIdentity; email: string; compact?: boolean }) {
  const [asking, setAsking] = useState(false);
  useVault(); // re-render after pins change (every vault is synced again)
  const p = personState(identity, email);
  if (p.status === "self") return compact ? null : <span className="badge badge-ok">You</span>;
  if (p.status === "invalid" || !p.fingerprint || !p.hash)
    return <span className="badge badge-warn">{compact ? "Keys can't be checked" : "These keys can't be checked. Don't share with this account."}</span>;
  const changed = p.status === "changed" || p.status === "email_conflict";
  const label = p.pinnedEmail || emailText(email);
  return (
    <>
      <span className="fingerprint-s" title={p.signing ? "Identity fingerprint" : "Public key fingerprint"}>
        {p.fingerprint}
      </span>
      <PinBadge pin={p.status} verified={p.verified} />
      {!p.verified && (
        <button type="button" className={`btn btn-text btn-sm${changed ? " btn-danger" : ""}`} onClick={() => setAsking(true)}>
          {changed ? "Compare and trust…" : "Verify…"}
        </button>
      )}
      {asking && (
        <VerifyDialog
          identity={identity}
          label={label}
          fingerprint={p.fingerprint}
          hash={p.hash}
          changed={changed}
          conflict={p.status === "email_conflict"}
          onClose={() => setAsking(false)}
        />
      )}
    </>
  );
}

/** A share's signer: "Signed by …", fingerprint, pin state and "Verify…". */
export function SignerTrust({ signer }: { signer: SignerView }) {
  const [asking, setAsking] = useState(false);
  return (
    <div className="field">
      <span>{signerText(signer)}</span>
      {signer.listedAs && <span className="field-hint">{signer.listedAs}</span>}
      <div className="row row-wrap">
        <span className="fingerprint-s" title="Identity fingerprint">
          {signer.fingerprint}
        </span>
        <PinBadge pin={signer.pin} verified={signer.verified} />
        {!signer.verified && (
          <button type="button" className="btn btn-text btn-sm" onClick={() => setAsking(true)}>
            Verify…
          </button>
        )}
      </div>
      {(signer.pin === "new" || signer.pin === "upgraded") && (
        <span className="field-hint">First time PassAuth sees {signer.label}: compare this fingerprint with them before you accept.</span>
      )}
      {asking && (
        <VerifyDialog identity={signer.identity} label={signer.label} fingerprint={signer.fingerprint} hash={signer.hash} changed={false} onClose={() => setAsking(false)} />
      )}
    </div>
  );
}

const ROLE: Record<string, string> = { owner: "Owner", admin: "Admin", write: "Can edit", read: "Can view" };
const CHANGE: Record<string, string> = { added: "New in this vault", role_changed: "Access changes", identity_changed: "Keys differ from the signed list" };

/**
 * The member review before a vault's members are signed (the first signed list: every member with fingerprint and pin
 * state, compared out of band) or before going on without people the signed list names. Confirming passes exactly this
 * list's digest and the missing people's user ids.
 */
export function ReviewDialog({
  review,
  title,
  action,
  onConfirm,
  onClose,
}: {
  review: ReviewView;
  title: string;
  action: string;
  onConfirm: (confirmed: Confirmation) => Promise<void>;
  onClose: () => void;
}) {
  return (
    <ConfirmDialog
      title={title}
      subtitle={review.first ? "Check every member" : "Some people are no longer in this vault"}
      icon="shield"
      danger={false}
      action={action}
      busyAction="Working…"
      onConfirm={() =>
        onConfirm({
          digest: review.digest,
          missing: review.missing.map((m) => m.userId),
          // The emails shown here are the ones pinned and signed (the digest doesn't cover emails).
          emails: Object.fromEntries(review.members.filter((m) => !m.isSelf && m.email).map((m) => [m.userId, m.email])),
        })
      }
      onClose={onClose}
    >
      {review.first && (
        <div className="alert alert-warn small" role="note">
          {FIRST_SIGNED} Your signature vouches that the vault's key goes to exactly these people with these roles. Don't continue if a fingerprint doesn't
          match.
        </div>
      )}
      <div className="fields" role="list" aria-label="Members">
        {review.members.map((m) => (
          <div key={m.userId} role="listitem">
            <span className="grow">
              <span className="row-title">{m.label}</span>
              {m.listedAs && <span className="row-sub">{m.listedAs}</span>}
              {!m.isSelf && (
                <span className="row row-wrap">
                  <span className="fingerprint-s" title="Identity fingerprint">
                    {m.fingerprint}
                  </span>
                  <PinBadge pin={m.pin} verified={m.verified} />
                  {!review.first && m.change !== "same" && <span className="badge badge-attn">{CHANGE[m.change] ?? m.change}</span>}
                </span>
              )}
            </span>
            <span className="badge">{ROLE[m.role] ?? m.role}</span>
          </div>
        ))}
      </div>
      {review.missing.length > 0 && (
        <p className="card-text">
          The vault's signed list of members names {review.missing.map((m) => m.label).join(", ")}, but your server no longer lists{" "}
          {review.missing.length === 1 ? "them" : "these people"} in this vault: they left, declined or deleted their account. PassAuth leaves them out of the
          new list{review.missing.length === 1 ? "" : "s"}.
        </p>
      )}
    </ConfirmDialog>
  );
}

/** One line per person whose keys changed, with "Compare and trust…". */
function KeyChangeRow({ change }: { change: KeyChange }) {
  const [asking, setAsking] = useState(false);
  return (
    <li>
      <span>
        {change.status === "email_conflict" ? conflictText(change.email) : `${cleanText(change.email) || "Someone"}'s keys changed.`}
      </span>{" "}
      <button type="button" className="link" onClick={() => setAsking(true)}>
        Compare and trust…
      </button>
      {asking && (
        <VerifyDialog
          identity={change.identity}
          label={change.email}
          fingerprint={change.fingerprint}
          hash={change.hash}
          changed
          conflict={change.status === "email_conflict"}
          onClose={() => setAsking(false)}
        />
      )}
    </li>
  );
}

/**
 * Vaults and invitations signed sharing refused, people whose keys changed, vaults waiting for consent, and sharing
 * paused on this device: for the notices above the item list (`link`) and Settings → Vaults & sharing.
 */
export function SigningNotices({ link = false }: { link?: boolean }) {
  const { blockedVaults, keyChanges, signingNotice, consents } = useVault();
  if (!blockedVaults.length && !keyChanges.length && !signingNotice && !(link && consents.length)) return null;
  const reasons = [...new Set(blockedVaults.map((b) => b.reason))];
  return (
    <div className="alert alert-warn small notice" role="alert">
      <div className="grow stack-s">
        {signingNotice && <span>{signingNotice}</span>}
        {blockedVaults.length > 0 && (
          <span>
            <Icon name="shield" size={14} /> {blockedVaults.length === 1 ? "A shared vault is locked:" : `${blockedVaults.length} shared vaults are locked:`}{" "}
            {reasons.join(" ")}
          </span>
        )}
        {link && consents.length > 0 && (
          <span>
            {consents.length === 1 ? "Your server added a shared vault to your account." : `Your server added ${consents.length} shared vaults to your account.`}{" "}
            Nothing from {consents.length === 1 ? "it" : "them"} is used until you accept.
          </span>
        )}
        {keyChanges.length > 0 && (
          <ul>
            {keyChanges.map((c) => (
              <KeyChangeRow key={c.identity.user_id} change={c} />
            ))}
          </ul>
        )}
        {link && (
          <div className="row">
            <Link to="/settings/vaults">Vaults & sharing</Link>
          </div>
        )}
      </div>
    </div>
  );
}
