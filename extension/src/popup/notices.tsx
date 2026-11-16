/**
 * Quiet notices at the top of the vault list:
 * - why the last fill on this tab's page didn't work ("Why PassAuth couldn't fill this page: …"), from the inline menu,
 *   the right-click menu or the fill shortcut (background/fill-problems.ts; gone when the tab navigates);
 * - what the server's policies still ask of the account (`policy_violations`), each linking to the place in the web
 *   vault that fixes it;
 * - vault invitations waiting in the web vault (servers with `vault_invitations`), linking to Settings → Vaults &
 *   sharing there;
 * - sign-ins on other devices put off with "Not now" (sign-in-requests.tsx), with "Review";
 * - signed sharing (background/signed-sharing.ts): shared vaults that failed a check and aren't used, a person whose
 *   keys changed (with their new fingerprint and "Trust the new key" once the user compared it), account-wide warnings,
 *   and invitations that can't be accepted as they are.
 * The policy, invitation and sharing notices can be dismissed for this browser session; they come back when their set
 * changes.
 */
import { Icon } from "@web/components/ui";
import { type ReactNode, useEffect, useState } from "react";
import { callPopup } from "../shared/protocol";
import { DISMISSED_KEY, FILL_PROBLEM_PREFIX } from "../shared/storage-keys";
import type { ItemList, PolicyNotices, SharingNotice } from "../shared/types";
import type { Ctx } from "./ctx";

type Dismissed = { policy?: string; invitations?: string; sharing?: string };

/** "1 vault invitation is waiting", "3 vault invitations are waiting". */
export const invitationsText = (n: number) => (n === 1 ? "1 vault invitation is waiting" : `${n} vault invitations are waiting`);

function Notice({ tone, children, onDismiss }: { tone: "warn" | "info"; children: ReactNode; onDismiss: () => void }) {
  return (
    <div className={`alert alert-${tone} small notice`} role="note">
      <div className="grow">{children}</div>
      <button type="button" className="btn btn-icon" aria-label="Dismiss" title="Dismiss" onClick={onDismiss}>
        <Icon name="close" size={16} />
      </button>
    </div>
  );
}

const openTab = (url: string) => void chrome.tabs.create({ url });

/**
 * A shared vault the server added without the account ever accepting it (or whose key was replaced on a vault never
 * seen signed): who signed it with their fingerprint, or the key id of an unsigned one, and Accept (after a
 * confirmation). Only a signed vault the core marks declinable can be declined (in the web vault); an unsigned one that can't be accepted stays
 * locked with "Ask the vault's owner to sign this vault." (no Decline: a server could make a real vault look like it).
 */
function WaitingVault({ w, vaultsUrl, refresh, notify }: { w: SharingNotice["waiting"][number]; vaultsUrl?: string; refresh: () => void; notify: (t: string) => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const s = w.signer;
  async function accept() {
    setBusy(true);
    try {
      await callPopup("sharing:accept", { vaultId: w.vaultId, token: w.token });
      notify(`${w.name || "The vault"} is accepted.`);
      refresh();
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  }
  return (
    <span>
      {w.text}{" "}
      {s && (
        <>
          Signed by {s.pinned ? s.email : `${s.email || "someone"} (as your server lists them)`}
          {s.pinned && s.listedAs ? `, listed by your server as ${s.listedAs}` : ""}, fingerprint <span className="mono">{s.fingerprint}</span>
          {s.verified ? " (verified)" : ""}.{" "}
        </>
      )}
      {w.note ? `${w.note} ` : ""}
      {!s && w.keyId && (
        <>
          Key id <span className="mono">{w.keyId}</span>.{" "}
        </>
      )}
      {w.acceptable && !confirming && (
        <button type="button" className="link" disabled={busy} onClick={() => setConfirming(true)}>
          Accept…
        </button>
      )}
      {w.acceptable && confirming && (
        <>
          {w.replaced
            ? s
              ? "Accept only if you compared this fingerprint with them and someone in this vault just replaced its key."
              : "Accept only if someone in this vault just replaced its key."
            : w.firstSigned && s
              ? "Accept only if you compared this fingerprint with them."
              : s
                ? "Accept only if you expected this vault from them."
                : "Accept only if you expected this vault, with this key id."}{" "}
          <button type="button" className="link" disabled={busy} onClick={() => void accept()}>
            I expected it: accept
          </button>{" "}
          <button type="button" className="link" disabled={busy} onClick={() => setConfirming(false)}>
            Not now
          </button>
        </>
      )}{" "}
      {vaultsUrl && s && w.declinable && (
        <button type="button" className="link" onClick={() => openTab(vaultsUrl)}>
          Decline in the web vault
        </button>
      )}
    </span>
  );
}

/** "PassAuth couldn't verify this shared vault…", or for several the count, then each changed key, waiting vault and warning. */
function SharingLines({ sharing, refresh, notify }: { sharing: SharingNotice; refresh: () => void; notify: (t: string) => void }) {
  const [busy, setBusy] = useState("");
  const changed = sharing.refused.filter((r) => r.changed);
  const others = sharing.refused.filter((r) => !r.changed);
  // One sentence per distinct reason: several vaults usually fail for the same one.
  const reasons = [...new Set(others.map((r) => r.reason))];
  const seen = new Set<string>();
  async function trust(userId: string, fingerprint: string) {
    setBusy(userId);
    try {
      await callPopup("sharing:trust", { userId, fingerprint });
      notify("The new key is trusted. PassAuth checked the vaults it signed again.");
      refresh();
    } catch (e) {
      notify(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }
  return (
    <>
      {reasons.map((reason) => {
        const n = others.filter((r) => r.reason === reason).length;
        return (
          <span key={reason}>
            {n > 1 ? `${n} shared vaults: ` : ""}
            {reason}
          </span>
        );
      })}
      {changed.map((r) => {
        const c = r.changed!;
        if (seen.has(`${c.kind}:${c.userId}`)) return null;
        seen.add(`${c.kind}:${c.userId}`);
        return (
          <span key={`${c.kind}:${c.userId}`}>
            {r.reason} {c.kind === "changed" ? "New fingerprint" : "Fingerprint of the new account"}: <span className="mono">{c.fingerprint}</span>.{" "}
            {c.kind === "changed" && (
              <button type="button" className="link" disabled={busy === c.userId} onClick={() => void trust(c.userId, c.fingerprint)}>
                I compared it: trust the new key
              </button>
            )}
          </span>
        );
      })}
      {sharing.waiting.map((w) => (
        <WaitingVault key={w.vaultId} w={w} vaultsUrl={sharing.vaultsUrl} refresh={refresh} notify={notify} />
      ))}
      {sharing.warnings.map((w) => (
        <span key={w}>{w}</span>
      ))}
      {sharing.invitations.map((i) => (
        <span key={i.vaultId}>{i.text}</span>
      ))}
    </>
  );
}

export function Notices({ ctx, data, tabId }: { ctx: Ctx; data: ItemList | null; tabId: number | undefined }) {
  const [dismissed, setDismissed] = useState<Dismissed>({});
  const [policy, setPolicy] = useState<PolicyNotices | null>(null);
  const [problemGone, setProblemGone] = useState(false);

  useEffect(() => {
    chrome.storage.session.get(DISMISSED_KEY).then(
      (r) => setDismissed((r[DISMISSED_KEY] as Dismissed | undefined) ?? {}),
      () => {},
    );
    // Asked once per popup (the background keeps the answer for a few minutes); none on failure.
    callPopup("policyNotices").then(setPolicy, () => {});
  }, []);

  const dismiss = (kind: keyof Dismissed, key: string) => {
    const next = { ...dismissed, [kind]: key };
    setDismissed(next);
    void chrome.storage.session.set({ [DISMISSED_KEY]: next }).catch(() => {});
  };

  const problem = problemGone ? undefined : data?.fillProblem;
  const invitations = data?.invitations;
  const policyShown = policy && policy.notices.length > 0 && dismissed.policy !== policy.key ? policy : null;
  const invitesShown = invitations && invitations.count > 0 && dismissed.invitations !== invitations.key ? invitations : null;
  const signIns = ctx.signIns && ctx.signIns.putOff > 0 ? ctx.signIns : null;
  const sharing = data?.sharing;
  const sharingShown = sharing && dismissed.sharing !== sharing.key ? sharing : null;
  if (!problem && !policyShown && !invitesShown && !signIns && !sharingShown) return null;
  return (
    <div className="notices">
      {signIns && (
        // Not dismissible: a sign-in waits for an answer until it is given or the request expires.
        <div className="alert alert-warn small notice" role="note">
          <div className="grow">
            <span>
              {signIns.putOff === 1 ? "A sign-in on another device is waiting for your approval." : `${signIns.putOff} sign-ins on other devices are waiting for your approval.`}{" "}
              <button type="button" className="link" onClick={signIns.review}>
                Review
              </button>
            </span>
          </div>
        </div>
      )}
      {problem && (
        <Notice
          tone="warn"
          onDismiss={() => {
            setProblemGone(true);
            if (tabId !== undefined) void chrome.storage.session.remove(`${FILL_PROBLEM_PREFIX}${tabId}`).catch(() => {});
          }}
        >
          <span>Why PassAuth couldn't fill this page: {problem}</span>
        </Notice>
      )}
      {policyShown && (
        <Notice tone="warn" onDismiss={() => dismiss("policy", policyShown.key)}>
          {policyShown.notices.map((n) => (
            <span key={n.text}>
              {n.text}{" "}
              {n.url && (
                <button type="button" className="link" onClick={() => openTab(n.url!)}>
                  {n.label ?? "Open the web vault"}
                </button>
              )}
            </span>
          ))}
        </Notice>
      )}
      {sharingShown && (
        <Notice tone="warn" onDismiss={() => dismiss("sharing", sharingShown.key)}>
          <SharingLines sharing={sharingShown} refresh={() => ctx.go({ tab: "vault", page: "list" })} notify={ctx.notify} />
        </Notice>
      )}
      {invitesShown && (
        <Notice tone="info" onDismiss={() => dismiss("invitations", invitesShown.key)}>
          <span>
            {invitationsText(invitesShown.count)}.{" "}
            <button type="button" className="link" onClick={() => openTab(`${ctx.state.server}/settings/vaults`)}>
              Open in the web vault
            </button>
          </span>
        </Notice>
      )}
    </div>
  );
}
