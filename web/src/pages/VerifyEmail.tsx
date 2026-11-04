import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { LogoMark } from "../components/Logo";
import { api, friendlyError } from "../lib/api";

const requests = new Map<string, Promise<unknown>>();
function verifyOnce(token: string) {
  let p = requests.get(token);
  if (!p) requests.set(token, (p = api("/auth/verify-email", { body: { token }, auth: false })));
  return p;
}

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const [state, setState] = useState<"working" | "ok" | string>("working");

  const token = params.get("token");
  useEffect(() => {
    if (!token) return setState("This link is incomplete. Open the link from your email again.");
    // The token works once: send it once per page load, even when React runs the effect twice.
    verifyOnce(token)
      .then(() => setState("ok"))
      .catch((e) => setState(friendlyError(e)));
  }, [token]);

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>{state === "ok" ? "Email confirmed" : state === "working" ? "Confirming your email…" : "We couldn't confirm your email"}</h1>
        </div>
        {state !== "working" && (
          <div className="auth-panel stack">
            {state === "ok" ? <p>Your email address is confirmed. You can sign in now.</p> : <div className="alert alert-error">{state}</div>}
            <Link className="btn btn-accent btn-block" to="/login">
              Go to sign in
            </Link>
          </div>
        )}
      </div>
    </main>
  );
}
