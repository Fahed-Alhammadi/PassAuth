// Two-step login pieces shared by the web vault settings and the admin page.
import { useCallback, useState } from "react";
import { downloadFile } from "../lib/kit";
import { server } from "../lib/server";
import { ActionRow, Modal, SheetActions, copySecret } from "./ui";
import "../styles/settings.css";

export function CodeField({
  id,
  value,
  onChange,
  label = "Verification code",
  autoFocus,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  label?: string;
  autoFocus?: boolean;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input mono code-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={11}
        spellCheck={false}
        autoFocus={autoFocus}
      />
    </div>
  );
}

export function RecoveryCodesModal({
  codes,
  onClose,
  title = "PassAuth recovery codes",
  intro = "If you lose your phone or can't get email, a recovery code lets you sign in.",
}: {
  codes: string[];
  onClose: () => void;
  /** First line of the downloaded file, and its name. */
  title?: string;
  intro?: string;
}) {
  const text = codes.join("\n");
  const [saved, setSaved] = useState(false);
  const [done, setDone] = useState<{ download?: boolean; copy?: boolean }>({});
  // They're shown only once: Escape or a click outside must not throw them away.
  const close = useCallback(() => {
    if (saved) onClose();
  }, [saved, onClose]);
  return (
    <Modal title="Save your recovery codes" subtitle="Shown only once. Each code works once." icon="note" closable={false} onClose={close}>
      <p className="card-text">{intro}</p>
      <div className="codes recovery-codes" aria-label="Recovery codes">
        {codes.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </div>
      <div className="choices">
        <ActionRow
          icon="download"
          title="Download recovery codes"
          sub={`A text file with all ${codes.length} codes`}
          done={done.download ? "Downloaded. Keep the file somewhere safe." : undefined}
          onClick={() => {
            downloadFile(`${title}.txt`, `${title}\n${server.origin()}\n\nEach code works once.\n\n${text}\n`);
            setDone((d) => ({ ...d, download: true }));
          }}
        />
        <ActionRow
          icon="copy"
          title="Copy all codes"
          sub="To paste into a note you keep safe"
          done={done.copy ? "Copied" : undefined}
          onClick={async () => {
            if (await copySecret(text, "Recovery codes copied")) setDone((d) => ({ ...d, copy: true }));
          }}
        />
      </div>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I saved my recovery codes somewhere safe</span>
      </label>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" disabled={!saved} onClick={onClose}>
          Done
        </button>
      </SheetActions>
    </Modal>
  );
}
