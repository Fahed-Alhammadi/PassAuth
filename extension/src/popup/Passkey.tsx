import { useEffect, useState, type FormEvent } from "react";
import { LogoMark } from "@web/components/Logo";
import { Icon } from "@web/components/ui";
import { send } from "../shared/messages";

/** Save target "create a new login" (matches NEW_LOGIN in background/passkey-handler.ts). */
const NEW_LOGIN = "new";

interface Info {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string; preferred?: boolean }[];
  /** The site requires user verification: confirm with the master password. */
  needsPassword: boolean;
}

/** Confirmation window for passkey creation and sign-in. */
export function PasskeyConfirm({ requestId }: { requestId: string }) {
  const [info, setInfo] = useState<Info | null | undefined>(undefined);
  const [choice, setChoice] = useState<string | undefined>();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    send<Info | null>({ type: "passkey:pending", requestId }).then((i) => {
      setInfo(i);
      // Saving: the best matching login for this exact site is preselected, else a new login.
      setChoice(i?.kind === "create" ? (i.candidates.find((c) => c.preferred)?.credentialId ?? NEW_LOGIN) : i?.candidates[0]?.credentialId);
    });
  }, [requestId]);

  const decide = async (accept: boolean, fallback = false) => {
    setBusy(true);
    setError("");
    try {
      await send({ type: "passkey:decide", requestId, accept, credentialId: choice, fallback, password: accept && info?.needsPassword ? password : undefined });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void decide(true);
  };

  if (info === undefined) return null;
  if (!info) {
    return (
      <div className="pop-auth">
        <p>This request has expired. Try again on the website.</p>
        <button className="btn" onClick={() => window.close()}>
          Close
        </button>
      </div>
    );
  }

  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="logo">
        <LogoMark size={44} />
      </div>
      <h1>{info.kind === "create" ? "Save a passkey in PassAuth?" : "Sign in with a passkey"}</h1>
      <div className="pk-site">{info.rpId}</div>
      {info.kind === "create" ? (
        <p className="small">
          {info.userName ? (
            <>
              This creates a passkey for <strong>{info.userName}</strong>. It is stored encrypted in your vault and works on every device where you use PassAuth.
            </>
          ) : (
            "The passkey is stored encrypted in your vault and works on every device where you use PassAuth."
          )}
        </p>
      ) : null}
      {info.kind === "create" && info.candidates.length > 0 && (
        <div className="stack-s" role="radiogroup" aria-label="Save the passkey in">
          <span className="small muted">Save in</span>
          {info.candidates.map((c) => (
            <button key={c.credentialId} type="button" role="radio" className="pk-choice" aria-checked={choice === c.credentialId} aria-pressed={choice === c.credentialId} onClick={() => setChoice(c.credentialId)}>
              <Icon name="key" />
              <span className="grow">
                <span style={{ display: "block", fontWeight: 500 }}>{c.itemName}</span>
                <span className="small muted">{c.userName || "No user name"}</span>
              </span>
            </button>
          ))}
          <button type="button" role="radio" className="pk-choice" aria-checked={choice === NEW_LOGIN} aria-pressed={choice === NEW_LOGIN} onClick={() => setChoice(NEW_LOGIN)}>
            <Icon name="plus" />
            <span className="grow">
              <span style={{ display: "block", fontWeight: 500 }}>New login</span>
              <span className="small muted">{info.rpId}</span>
            </span>
          </button>
        </div>
      )}
      {info.kind === "get" && (
        <div className="stack-s" role="radiogroup" aria-label="Choose an account">
          {info.candidates.map((c) => (
            <button key={c.credentialId} type="button" className="pk-choice" aria-pressed={choice === c.credentialId} onClick={() => setChoice(c.credentialId)}>
              <Icon name="key" />
              <span className="grow">
                <span style={{ display: "block", fontWeight: 500 }}>{c.userName || "Account"}</span>
                <span className="small muted">{c.itemName}</span>
              </span>
            </button>
          ))}
        </div>
      )}
      {info.needsPassword && (
        <div className="field">
          <label htmlFor="pk-password">This site asks PassAuth to confirm it's you. Enter your master password.</label>
          <input
            id="pk-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoFocus
            required
          />
        </div>
      )}
      {error && (
        <p className="alert alert-error small" role="alert">
          {error}
        </p>
      )}
      <button type="submit" className="btn btn-accent btn-block" disabled={busy} autoFocus={!info.needsPassword}>
        {busy ? "Checking…" : info.kind === "create" ? "Save passkey" : "Sign in"}
      </button>
      <button type="button" className="btn btn-block" disabled={busy} onClick={() => decide(false, true)}>
        Use another device or security key
      </button>
      <button type="button" className="btn btn-ghost" disabled={busy} onClick={() => decide(false)}>
        Cancel
      </button>
    </form>
  );
}
