import { useCallback, useEffect, useState } from "react";
import { LogoMark } from "../components/Logo";
import { RecoveryCodesModal } from "../components/TwoStep";
import { ErrorText, Icon, SheetActions } from "../components/ui";
import { api, friendlyError } from "../lib/api";
import { continueAfterTwoStep, useVault } from "../lib/vault";
import { signOut as warnedSignOut } from "../components/OfflineChanges";
import { AddPasskeyModal, EmailCard, PasskeysCard, TotpCard, type AccountInfo } from "./Settings";

/**
 * The server requires two-step login (an account policy) and this account has no method yet, so the server refuses
 * everything else. This page offers only the methods (the same cards as Settings → Two-step login) and signing out;
 * once one is on, the recovery codes are shown and the vault opens as usual.
 */
export function TwoStepRequiredPage() {
  const { email } = useVault();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [addingKey, setAddingKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setAccount(await api<AccountInfo>("/account"));
      setLoadError(null);
    } catch (e) {
      setLoadError(`Couldn't load your account. ${friendlyError(e)}`);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const on = (account?.two_factor.length ?? 0) > 0;

  async function proceed() {
    setBusy(true);
    setError(null);
    try {
      await continueAfterTwoStep();
    } catch (e) {
      setError(friendlyError(e));
      setBusy(false);
    }
  }

  /** A method was turned on: the first one comes with recovery codes, which are shown before the vault opens. */
  async function enabled(recovery: string[] | null) {
    await reload();
    if (recovery?.length) setCodes(recovery);
    else await proceed();
  }

  const signOut = (
    <button type="button" className="btn btn-text" onClick={() => void warnedSignOut()} disabled={busy}>
      Sign out
    </button>
  );

  return (
    <main className="auth">
      <div className="auth-card auth-card-wide">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>Your server requires two-step login</h1>
          <p className="muted">
            {email ? `Set up a second step for ${email} to open your vault. ` : "Set up a second step to open your vault. "}
            It's asked for after your master password when you sign in on a new device, so a stolen password isn't enough.
          </p>
        </div>

        {on ? (
          <div className="auth-panel stack">
            <div className="sheet-context">
              <span className="tile" aria-hidden="true">
                <Icon name="shield" size={20} />
              </span>
              <div className="grow">
                <h2 className="sheet-title">Two-step login is on</h2>
                <p className="sheet-sub">Your vault can open now.</p>
              </div>
            </div>
            <ErrorText error={error} />
            <SheetActions quiet={signOut}>
              <button type="button" className="btn btn-accent btn-block" disabled={busy} onClick={proceed}>
                {busy ? "Opening vault…" : "Continue"}
              </button>
            </SheetActions>
          </div>
        ) : account ? (
          <div className="settings-section">
            <TotpCard on={false} onEnabled={enabled} />
            <EmailCard on={false} available={account.email_enabled} email={account.email} onEnabled={enabled} />
            <PasskeysCard account={account} onAdd={() => setAddingKey(true)} />
            <p className="small muted">You get recovery codes with your first method. Keep them somewhere safe: they let you sign in if you lose it.</p>
            <ErrorText error={error} />
          </div>
        ) : (
          <div className="auth-panel stack">
            {loadError ? (
              <>
                <ErrorText error={loadError} />
                <div className="row">
                  <button type="button" className="btn" onClick={reload}>
                    Try again
                  </button>
                </div>
              </>
            ) : (
              <p className="muted" role="status">
                Loading…
              </p>
            )}
          </div>
        )}

        {!on && <div className="auth-foot">{signOut}</div>}
      </div>

      {addingKey && (
        <AddPasskeyModal
          onAdded={async (recovery) => {
            setAddingKey(false);
            await enabled(recovery);
          }}
          onClose={() => setAddingKey(false)}
        />
      )}
      {codes && (
        <RecoveryCodesModal
          codes={codes}
          onClose={() => {
            setCodes(null);
            void proceed();
          }}
        />
      )}
    </main>
  );
}
