import { useEffect, useState, type FormEvent } from "react";
import { LogoMark } from "@web/components/Logo";
import { Icon } from "@web/components/ui";
import { send } from "../shared/messages";

interface Info {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string }[];
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
      setChoice(i?.candidates[0]?.credentialId);
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
      ) : (
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
