import { useEffect, useState } from "react";
import { LogoMark } from "@web/components/Logo";
import { Icon } from "@web/components/ui";
import { send } from "../shared/messages";

interface Info {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string }[];
}

/** Confirmation window for passkey creation and sign-in. */
export function PasskeyConfirm({ requestId }: { requestId: string }) {
  const [info, setInfo] = useState<Info | null | undefined>(undefined);
  const [choice, setChoice] = useState<string | undefined>();

  useEffect(() => {
    send<Info | null>({ type: "passkey:pending", requestId }).then((i) => {
      setInfo(i);
      setChoice(i?.candidates[0]?.credentialId);
    });
  }, [requestId]);

  const decide = (accept: boolean, fallback = false) => send({ type: "passkey:decide", requestId, accept, credentialId: choice, fallback });

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
    <div className="pop-auth">
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
            <button key={c.credentialId} className="pk-choice" aria-pressed={choice === c.credentialId} onClick={() => setChoice(c.credentialId)}>
              <Icon name="key" />
              <span className="grow">
                <span style={{ display: "block", fontWeight: 500 }}>{c.userName || "Account"}</span>
                <span className="small muted">{c.itemName}</span>
              </span>
            </button>
          ))}
        </div>
      )}
      <button className="btn btn-accent btn-block" onClick={() => decide(true)} autoFocus>
        {info.kind === "create" ? "Save passkey" : "Sign in"}
      </button>
      <button className="btn btn-block" onClick={() => decide(false, true)}>
        Use another device or security key
      </button>
      <button className="btn btn-ghost" onClick={() => decide(false)}>
        Cancel
      </button>
    </div>
  );
}
