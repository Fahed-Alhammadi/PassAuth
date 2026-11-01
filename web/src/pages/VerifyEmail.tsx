import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { LogoMark } from "../components/Logo";
import { api, errorMessage } from "../lib/api";

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const [state, setState] = useState<"working" | "ok" | string>("working");

  useEffect(() => {
    const token = params.get("token");
    if (!token) return setState("This link is incomplete. Open the link from your email again.");
    api("/auth/verify-email", { body: { token }, auth: false })
      .then(() => setState("ok"))
      .catch((e) => setState(errorMessage(e)));
  }, [params]);

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
            <Link className="btn btn-brass btn-block" to="/login">
              Go to sign in
            </Link>
          </div>
        )}
      </div>
    </main>
  );
}
