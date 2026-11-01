import { useEffect, useState, type ReactNode } from "react";
import { estimateBits, generatePassword, totpCode } from "../lib/vault";

// ------------------------------------------------------------------ icons

const paths = {
  copy: "M8 8h11v13H8zM5 16H4V3h11v1",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  eyeOff: "M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2",
  dice: "M4 4h16v16H4zM8.5 8.5h.01M15.5 15.5h.01M15.5 8.5h.01M8.5 15.5h.01M12 12h.01",
  plus: "M12 5v14M5 12h14",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-5-5",
  star: "M12 3l2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9z",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  external: "M14 4h6v6M20 4l-9 9M18 14v6H4V6h6",
  lock: "M6 11h12v10H6zM8 11V8a4 4 0 1 1 8 0v3",
  key: "M15 9a4 4 0 1 0-3.9 4.9L4 21v-3h3v-3h3l1.1-1.1A4 4 0 0 0 15 9z",
  vault: "M4 4h16v16H4zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM12 9v-1M12 16v-1M4 9h-1M4 15H3",
  note: "M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h5",
  card: "M3 6h18v12H3zM3 10h18M7 15h3",
  person: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  terminal: "M4 5h16v14H4zM8 10l3 2-3 2M13 15h3",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  upload: "M12 16V4M7 9l5-5 5 5M4 20h16",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  share: "M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.6 13.5l6.8 4M15.4 6.5l-6.8 4",
  back: "M15 18l-6-6 6-6",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  restore: "M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5",
  wand: "M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8l1.4 1.4M17.8 6.2l1.4-1.4M3 21l9-9",
} as const;

export type IconName = keyof typeof paths;

export function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}

// ------------------------------------------------------------------ toast

let showToast: (msg: string) => void = () => {};
export function toast(msg: string) {
  showToast(msg);
}

export function ToastHost() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    let t: number | undefined;
    showToast = (m) => {
      setMsg(m);
      clearTimeout(t);
      t = window.setTimeout(() => setMsg(null), 2200);
    };
    return () => clearTimeout(t);
  }, []);
  return msg ? (
    <div className="toast" role="status">
      {msg}
    </div>
  ) : null;
}

/** Copy and clear the clipboard after 30 s if it still holds the secret. */
export async function copySecret(value: string, label = "Copied") {
  await navigator.clipboard.writeText(value);
  toast(`${label}. Clipboard clears in 30 seconds.`);
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === value) await navigator.clipboard.writeText("");
    } catch {
      /* clipboard read not permitted; leave it */
    }
  }, 30_000);
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  return (
    <button type="button" className="btn-icon btn" title={label} aria-label={label} onClick={() => copySecret(value, `${label.replace(/^Copy /, "")} copied`)}>
      <Icon name="copy" />
    </button>
  );
}

// ------------------------------------------------------------- password

export function PasswordInput({
  value,
  onChange,
  generate,
  autoComplete = "current-password",
  autoFocus,
  id,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  generate?: boolean;
  autoComplete?: string;
  autoFocus?: boolean;
  id?: string;
  placeholder?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className="input-group">
      <input
        id={id}
        className="input mono"
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        spellCheck={false}
        placeholder={placeholder}
      />
      {generate && (
        <button type="button" className="btn btn-icon" title="Generate password" aria-label="Generate password" onClick={() => onChange(generatePassword(undefined))}>
          <Icon name="dice" />
        </button>
      )}
      <button type="button" className="btn btn-icon" aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow(!show)}>
        <Icon name={show ? "eyeOff" : "eye"} />
      </button>
    </div>
  );
}

export function StrengthMeter({ password }: { password: string }) {
  if (!password) return null;
  const bits = estimateBits(password);
  const [label, color, pct] =
    bits < 40 ? ["Weak", "var(--danger)", 25] : bits < 60 ? ["Fair", "var(--brass)", 50] : bits < 80 ? ["Good", "var(--patina)", 75] : ["Strong", "var(--patina)", 100];
  return (
    <div className="stack-s">
      <div className="meter" aria-hidden="true">
        <i style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="small muted">Strength: {label}</span>
    </div>
  );
}

// ------------------------------------------------------------------- TOTP

export function TotpView({ secret }: { secret: string }) {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(t);
  }, []);
  let code: { code: string; remaining: number; period: number };
  try {
    code = totpCode(secret, now);
  } catch {
    return <span className="small muted">Invalid authenticator key</span>;
  }
  const r = 14;
  const c = 2 * Math.PI * r;
  const pretty = code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code;
  return (
    <div className="totp">
      <svg className={`totp-ring${code.remaining <= 5 ? " low" : ""}`} width="36" height="36" viewBox="0 0 36 36" aria-hidden="true">
        <circle className="track" cx="18" cy="18" r={r} />
        <circle className="arc" cx="18" cy="18" r={r} strokeDasharray={c} strokeDashoffset={c * (1 - code.remaining / code.period)} />
      </svg>
      <span className="totp-code" aria-live="polite">
        {pretty}
      </span>
      <span className="small muted">{code.remaining}s</span>
      <CopyButton value={code.code} label="Copy code" />
    </div>
  );
}

// ----------------------------------------------------------------- modal

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export function ErrorText({ error }: { error: string | null }) {
  return error ? (
    <div className="alert alert-error" role="alert">
      {error}
    </div>
  ) : null;
}
