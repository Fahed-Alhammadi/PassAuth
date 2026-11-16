import { useEffect, useState } from "react";
import { friendlyError } from "../lib/api";
import { entryLabel } from "../lib/emergency";
import { RosterChangedError, loadServerRoster, startNewRoster, useServerRoster, type ServerRoster } from "../lib/emergency-client";
import { fingerprint } from "../lib/vault";
import { ConfirmPassword, ErrorText, toast } from "./ui";

/** A contact key's fingerprint, or null when it isn't a key. */
function safeFingerprint(publicKey: string): string | null {
  try {
    return fingerprint(publicKey);
  } catch {
    return null;
  }
}

/**
 * "Use the server's list": the way out when the server sends an older list of emergency contacts than one this device
 * opened, because the server's admin restored a backup. The list is shown for review first, with the names and keys
 * from inside it, each contact this device's own last list doesn't have marked; taking it needs the master password.
 */
export function UseServerListButton({ onDone }: { onDone?: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="link" onClick={() => setOpen(true)}>
        Use the server's list
      </button>
      {open && (
        <UseServerListDialog
          onClose={() => setOpen(false)}
          onDone={() => {
            setOpen(false);
            onDone?.();
          }}
        />
      )}
    </>
  );
}

function UseServerListDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [list, setList] = useState<ServerRoster | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () =>
    loadServerRoster().then(
      (l) => setList(l),
      (e) => setError(friendlyError(e)),
    );

  useEffect(() => {
    void load();
  }, []);

  return (
    <ConfirmPassword
      title="Use your server's list of emergency contacts?"
      icon="lifebuoy"
      action="Use the server's list"
      busyAction="Saving…"
      danger
      onClose={onClose}
      onConfirm={async (password) => {
        if (!list) throw new Error("Wait for the list to load, then try again.");
        try {
          await useServerRoster(list, password);
        } catch (e) {
          // Changed since it was shown: read it again and show it again, never written unseen.
          if (e instanceof RosterChangedError) {
            setList(null);
            void load();
          }
          throw e;
        }
        toast("This device uses your server's list of emergency contacts now");
        onDone();
      }}
    >
      <p className="card-text">
        Only do this if your server's admin restored a backup. Contacts you removed after that backup could get access to your personal vaults again. Check
        the list below before you continue.
      </p>
      {!list && !error && (
        <p className="muted" role="status">
          Loading…
        </p>
      )}
      {list &&
        (list.entries.length === 0 ? (
          <p className="card-text">The server's list has no contacts.</p>
        ) : (
          <ul className="stack-s" aria-label="Contacts on the server's list">
            {list.entries.map(({ entry, wouldReturn, removed }) => {
              const fp = safeFingerprint(entry.contactKey);
              return (
                <li key={entry.id}>
                  <div>
                    {entryLabel(entry)}
                    {removed ? (
                      <span className="badge"> Removed earlier: stays removed</span>
                    ) : (
                      wouldReturn && <span className="badge badge-attn"> Would get access again</span>
                    )}
                  </div>
                  <div className="small muted">Key fingerprint: {fp ?? "unknown"}</div>
                </li>
              );
            })}
          </ul>
        ))}
      <ErrorText error={error} />
    </ConfirmPassword>
  );
}

/**
 * "Start a new list": the way out when the server's list of emergency contacts doesn't open with the account's key.
 * A new, empty list (with the master password); contacts who hold keys then have to be confirmed again.
 */
export function StartNewListButton({ onDone }: { onDone?: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="link" onClick={() => setOpen(true)}>
        Start a new list
      </button>
      {open && (
        <ConfirmPassword
          title="Start a new list of emergency contacts?"
          icon="lifebuoy"
          action="Start a new list"
          busyAction="Saving…"
          onClose={() => setOpen(false)}
          onConfirm={async (password) => {
            await startNewRoster(password);
            setOpen(false);
            toast("New list of emergency contacts started. Confirm your contacts again.");
            onDone?.();
          }}
        >
          <p className="card-text">
            Your server's list can't be opened with your account's key, so PassAuth can't tell which contacts you trust. A new list starts empty: until you
            confirm them again, none of your contacts gets keys to new or changed vaults.
          </p>
        </ConfirmPassword>
      )}
    </>
  );
}
