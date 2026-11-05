import { useState, type FormEvent } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { LogoMark } from "@web/components/Logo";
import { ErrorText } from "@web/components/ui";
import { ConnectError, parseServer, probeServer } from "./server";

const WEBSITE = "https://fahed-alhammadi.github.io/PassAuth/";

/** First run, or after "Change server": ask where the user's PassAuth server is. */
export function Connect({ initial = "", onConnect }: { initial?: string; onConnect: (base: string) => void }) {
  const [address, setAddress] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const base = parseServer(address);
      await probeServer(base);
      onConnect(base);
    } catch (err) {
      setError(err instanceof ConnectError ? err.message : "Something went wrong. Try again.");
      setBusy(false);
    }
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>Connect to your server</h1>
          <p className="muted">PassAuth keeps your vault on a server you or your organisation run. Enter its address to get started.</p>
        </div>
        <form className="auth-panel stack" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="server">Server address</label>
            <input
              id="server"
              className="input"
              type="text"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="https://vault.example.com"
              inputMode="url"
              autoComplete="url"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              autoFocus
              disabled={busy}
            />
            <p className="small muted">
              The address you open PassAuth at in your browser, for example https://vault.example.com. Only https:// addresses work, except on this
              computer.
            </p>
          </div>
          <ErrorText error={error} />
          <button className="btn btn-accent btn-block" disabled={busy}>
            {busy ? "Connecting…" : "Connect"}
          </button>
        </form>
        <p className="auth-foot">
          Don't have a server yet? Ask whoever set up PassAuth for you, or{" "}
          <button type="button" className="link" onClick={() => void openUrl(WEBSITE)}>
            run your own
          </button>
          .
        </p>
      </div>
    </main>
  );
}
