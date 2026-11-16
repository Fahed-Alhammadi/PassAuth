/**
 * Quiet notices at the top of the vault list:
 * - why the last fill on this tab's page didn't work ("Why PassAuth couldn't fill this page: …"), from the inline menu,
 *   the right-click menu or the fill shortcut (background/fill-problems.ts; gone when the tab navigates);
 * - what the server's policies still ask of the account (`policy_violations`), each linking to the place in the web
 *   vault that fixes it;
 * - vault invitations waiting in the web vault (servers with `vault_invitations`), linking to Settings → Vaults &
 *   sharing there;
 * - sign-ins on other devices put off with "Not now" (sign-in-requests.tsx), with "Review".
 * The policy and invitation notices can be dismissed for this browser session; they come back when their set changes.
 */
import { Icon } from "@web/components/ui";
import { type ReactNode, useEffect, useState } from "react";
import { callPopup } from "../shared/protocol";
import { DISMISSED_KEY, FILL_PROBLEM_PREFIX } from "../shared/storage-keys";
import type { ItemList, PolicyNotices } from "../shared/types";
import type { Ctx } from "./ctx";

type Dismissed = { policy?: string; invitations?: string };

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
  if (!problem && !policyShown && !invitesShown && !signIns) return null;
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
