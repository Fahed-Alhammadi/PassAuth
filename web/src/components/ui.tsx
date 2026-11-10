import { isValidElement, useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { friendlyError } from "../lib/api";
import { getDesktop } from "../lib/platform";
import { server as serverConfig } from "../lib/server";
import { estimateBits, generatePassword, totpCode } from "../lib/vault";
import { LogoMark } from "./Logo";

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
  download: "M12 4v12M7 11l5 5 5-5M4 20h16",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  share: "M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.6 13.5l6.8 4M15.4 6.5l-6.8 4",
  back: "M15 18l-6-6 6-6",
  shield: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  restore: "M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5",
  wand: "M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8l1.4 1.4M17.8 6.2l1.4-1.4M3 21l9-9",
  more: "M6 12a1 1 0 1 1-2 0 1 1 0 0 1 2 0zM13 12a1 1 0 1 1-2 0 1 1 0 0 1 2 0zM20 12a1 1 0 1 1-2 0 1 1 0 0 1 2 0z",
  close: "M6 6l12 12M18 6L6 18",
  chevron: "M9 6l6 6-6 6",
  filter: "M4 6h16M7 12h10M10 18h4",
  dots: "M12 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2zM12 13a1 1 0 1 1 0-2 1 1 0 0 1 0 2zM12 20a1 1 0 1 1 0-2 1 1 0 0 1 0 2z",
  folder: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v5M12 8h.01",
  bell: "M6 9a6 6 0 1 1 12 0c0 6 3 8 3 8H3s3-2 3-8M10.3 21a1.9 1.9 0 0 0 3.4 0",
  sync: "M20 11a8 8 0 0 0-14.3-4.9L4 8M4 3v5h5M4 13a8 8 0 0 0 14.3 4.9L20 16M20 21v-5h-5",
  check: "M5 12.5l4.5 4.5L19 7.5",
  mail: "M3 6h18v12H3zM3 7l9 7 9-7",
  printer: "M7 8V3h10v5M7 17H4V8h16v9h-3M7 14h10v7H7z",
  desktop: "M3 4h18v12H3zM8 20h8M12 16v4",
  phone: "M7 2h10v20H7zM11 18h2",
  puzzle: "M10 4a2 2 0 1 1 4 0v2h5v5h-2a2 2 0 1 0 0 4h2v5H5v-5h2a2 2 0 1 0 0-4H5V6h5z",
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

/** The live region stays mounted so screen readers announce each message; only its text changes. */
export function ToastHost() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    let t: number | undefined;
    showToast = (m) => {
      setMsg(m);
      clearTimeout(t);
      t = window.setTimeout(() => setMsg(null), Math.max(4000, m.length * 60));
    };
    return () => clearTimeout(t);
  }, []);
  return (
    <div className="toast-region" role="status" aria-live="polite">
      {msg && <div className="toast">{msg}</div>}
    </div>
  );
}

/** Copy without the async Clipboard API (missing on plain-http servers). */
function legacyCopy(value: string): boolean {
  const ta = document.createElement("textarea");
  ta.value = value;
  ta.setAttribute("readonly", "");
  ta.style.cssText = "position:fixed;top:0;left:0;opacity:0;pointer-events:none";
  const active = document.activeElement as HTMLElement | null;
  document.body.append(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  active?.focus?.();
  return ok;
}

/** Copy and clear the clipboard after 30 s if it still holds the secret. Never throws. */
export async function copySecret(value: string, label = "Copied"): Promise<boolean> {
  label = label[0].toUpperCase() + label.slice(1);
  const desktop = getDesktop();
  if (desktop) {
    try {
      await desktop.copySecret(value);
      toast(`${label}. Clipboard clears in 30 seconds.`);
      return true;
    } catch {
      toast("Copying failed. Select the text and copy it yourself.");
      return false;
    }
  }
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      toast(`${label}. Clipboard clears in 30 seconds.`);
      setTimeout(async () => {
        try {
          if ((await navigator.clipboard.readText()) === value) await navigator.clipboard.writeText("");
        } catch {
          /* clipboard read not permitted; leave it */
        }
      }, 30_000);
      return true;
    } catch {
      /* fall back below */
    }
  }
  if (legacyCopy(value)) {
    toast(`${label}. Clear your clipboard when you're done: this connection doesn't allow PassAuth to do it.`);
    return true;
  }
  toast("Copying isn't available on this connection. Select the text and copy it yourself.");
  return false;
}

/** Website icon from the server's icon service, falling back to the item's initial. */
export function SiteIcon({ host, name, server = serverConfig.base, enabled = true }: { host: string; name: string; server?: string; enabled?: boolean }) {
  const [loaded, setLoaded] = useState(false);
  useEffect(() => setLoaded(false), [host]);
  return (
    <span className={loaded ? "avatar has-img" : "avatar"} aria-hidden="true">
      {enabled && host ? (
        <img
          src={`${server}/api/icons/${encodeURIComponent(host)}`}
          alt=""
          referrerPolicy="no-referrer"
          loading="lazy"
          className={loaded ? undefined : "pending"}
          onLoad={() => setLoaded(true)}
          onError={() => setLoaded(false)}
        />
      ) : null}
      {loaded ? null : (name.trim()[0] ?? "?").toUpperCase()}
    </span>
  );
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
  /** true = the web vault's generator; a function supplies another (e.g. the extension's). */
  generate?: boolean | (() => Promise<string>);
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
        data-autofocus={autoFocus ? "" : undefined}
        spellCheck={false}
        placeholder={placeholder}
      />
      {generate && (
        <button type="button" className="btn btn-icon" title="Generate password" aria-label="Generate password" onClick={async () => onChange(typeof generate === "function" ? await generate() : generatePassword(undefined))}>
          <Icon name="dice" />
        </button>
      )}
      <button type="button" className="btn btn-icon" aria-label={show ? "Hide password" : "Show password"} onClick={() => setShow(!show)}>
        <Icon name={show ? "eyeOff" : "eye"} />
      </button>
    </div>
  );
}

/** Bits below which sign-up and password changes warn that a master password is easy to guess. */
export const WEAK_BITS = 50;

/** Strength label shared by the meter and the sign-up check, so they never disagree. */
export function strength(bits: number): { label: string; color: string; pct: number } {
  if (bits < WEAK_BITS) return { label: "Weak", color: "var(--danger)", pct: 25 };
  if (bits < 65) return { label: "Fair", color: "var(--warn)", pct: 50 };
  if (bits < 80) return { label: "Good", color: "var(--ok)", pct: 75 };
  return { label: "Strong", color: "var(--ok)", pct: 100 };
}

export function StrengthMeter({ password }: { password: string }) {
  if (!password) return null;
  const { label, color, pct } = strength(estimateBits(password));
  return (
    <div className="stack-s">
      <div className="meter" aria-hidden="true">
        <i style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="small muted" role="status">
        Strength: {label}
      </span>
    </div>
  );
}

/** A labelled password input (label outside the input group, so the buttons don't become part of its name). */
export function PasswordField({ label, hint, ...props }: { label: string; hint?: ReactNode } & Parameters<typeof PasswordInput>[0]) {
  const auto = useId();
  const id = props.id ?? `pw-${auto}`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <PasswordInput {...props} id={id} />
      {hint}
    </div>
  );
}

// ------------------------------------------------------------------- TOTP

export function TotpView({ secret }: { secret: string }) {
  const gradient = `pa-ring-${useId().replace(/:/g, "")}`;
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
  const r = 16;
  const c = 2 * Math.PI * r;
  const pretty = code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code;
  const low = code.remaining <= 5;
  return (
    <div className="totp">
      <svg className={`totp-ring${low ? " low" : ""}`} width="40" height="40" viewBox="0 0 40 40" aria-hidden="true">
        <defs>
          {/* The shield gradient; userSpaceOnUse keeps it fixed while the arc shortens. */}
          <linearGradient id={gradient} gradientUnits="userSpaceOnUse" x1="0" y1="40" x2="40" y2="0">
            <stop offset="0" style={{ stopColor: "var(--ring-1)" }} />
            <stop offset="0.52" style={{ stopColor: "var(--ring-2)" }} />
            <stop offset="1" style={{ stopColor: "var(--ring-3)" }} />
          </linearGradient>
        </defs>
        <circle className="track" cx="20" cy="20" r={r} />
        <circle
          className="arc"
          cx="20"
          cy="20"
          r={r}
          strokeDasharray={c}
          strokeDashoffset={c * (1 - code.remaining / code.period)}
          style={low ? undefined : { stroke: `url(#${gradient})` }}
        />
      </svg>
      <span className="totp-code">{pretty}</span>
      <span className="totp-left">{code.remaining}s</span>
      <CopyButton value={code.code} label="Copy code" />
    </div>
  );
}

// ----------------------------------------------------------------- modal

/**
 * Dialog on the native <dialog>, laid out as a decision sheet: a brand bar with Close, a context row
 * (icon, title, what it is about), the content, then the actions (see SheetActions).
 * Focus is trapped inside, the page behind is inert, and focus returns to the opener on close. Mark the
 * control to focus first with `data-autofocus` (or autoFocus on PasswordInput); otherwise the first field
 * gets focus, then the first control of the content.
 */
export function Modal({
  title,
  subtitle,
  icon,
  tone,
  closable = true,
  onClose,
  children,
}: {
  title: string;
  /** What the decision is about: a site, an account, a vault. */
  subtitle?: ReactNode;
  /** Icon name for the tile beside the title, or an element (e.g. a site icon). */
  icon?: IconName | ReactNode;
  tone?: "danger";
  /** false hides Close for content that must be acknowledged (shown-once secrets). */
  closable?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const opener = document.activeElement as HTMLElement | null;
    let mounted = true;
    if (!el.open) el.showModal();
    const first =
      el.querySelector<HTMLElement>("[data-autofocus]") ??
      el.querySelector<HTMLElement>("input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled])") ??
      el.querySelector<HTMLElement>(".modal-body button:not([disabled]), .modal-body a[href]");
    first?.focus();
    // The browser can close a dialog on its own (e.g. repeated Escape): keep it open while it's rendered.
    const reopen = () => mounted && !el.open && el.isConnected && el.showModal();
    el.addEventListener("close", reopen);
    return () => {
      mounted = false;
      el.removeEventListener("close", reopen);
      if (el.open) el.close();
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  return (
    <dialog
      ref={ref}
      className="modal"
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        closeRef.current();
      }}
      onMouseDown={(e) => {
        // A press on the backdrop lands on the <dialog> itself, outside its box.
        if (e.target !== e.currentTarget) return;
        const r = e.currentTarget.getBoundingClientRect();
        if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) closeRef.current();
      }}
    >
      <div className="sheet-bar">
        <span className="sheet-brand">
          <span aria-hidden="true" className="row">
            <LogoMark size={18} />
          </span>
          PassAuth
        </span>
        {closable && (
          <button type="button" className="btn btn-icon" aria-label="Close" onClick={() => closeRef.current()}>
            <Icon name="close" />
          </button>
        )}
      </div>
      <div className="modal-body">
        <div className="sheet-context">
          {isValidElement(icon) ? (
            icon
          ) : typeof icon === "string" ? (
            <span className={tone === "danger" ? "tile tile-danger" : "tile"} aria-hidden="true">
              <Icon name={icon as IconName} size={20} />
            </span>
          ) : null}
          <div className="grow">
            <h2 id={titleId} className="sheet-title">
              {title}
            </h2>
            {subtitle && <p className="sheet-sub">{subtitle}</p>}
          </div>
        </div>
        {children}
      </div>
    </dialog>
  );
}

/** A sheet's actions: the one filled primary button (children), with the quiet text buttons on a row beneath. */
export function SheetActions({ children, quiet }: { children?: ReactNode; quiet?: ReactNode }) {
  return (
    <div className="sheet-actions">
      {children}
      {quiet && <div className="sheet-quiet">{quiet}</div>}
    </div>
  );
}

/** One row of a grouped `.choices` card that does something when pressed (download, print, open…). */
export function ActionRow({ icon, title, sub, done, onClick }: { icon: IconName; title: string; sub?: ReactNode; /** Set once it has been done, e.g. "Downloaded"; replaces `sub`. */ done?: string; onClick: () => void }) {
  return (
    <button type="button" className="choice" onClick={onClick}>
      <span className="tile" aria-hidden="true">
        <Icon name={icon} />
      </span>
      <span className="choice-text">
        <span className="choice-title">{title}</span>
        {done ? <span className="choice-sub done">{done}</span> : sub && <span className="choice-sub">{sub}</span>}
      </span>
      <span className={done ? "choice-trail done" : "choice-trail"} aria-hidden="true">
        <Icon name={done ? "check" : "chevron"} size={done ? 18 : 16} />
      </span>
    </button>
  );
}

/** Yes/no confirmation for an action that can't be undone or needs a second look. */
export function ConfirmDialog({
  title,
  subtitle,
  icon = "info",
  children,
  action,
  busyAction = "Working…",
  cancel = "Cancel",
  danger = true,
  confirmText,
  matchCase = true,
  onConfirm,
  onClose,
}: {
  title: string;
  subtitle?: ReactNode;
  icon?: IconName | ReactNode;
  children?: ReactNode;
  /** The primary button: a verb that says what happens. */
  action: string;
  busyAction?: string;
  cancel?: string;
  /** Destructive (the default): red primary, and Cancel gets the initial focus. */
  danger?: boolean;
  /** When set, the user must type this (e.g. the vault name) before the action is enabled. */
  confirmText?: string;
  /** false accepts any letter case for `confirmText` (email addresses). */
  matchCase?: boolean;
  onConfirm: () => void | Promise<void>;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const typedId = useId();
  const fold = (v: string) => (matchCase ? v.trim() : v.trim().toLowerCase());
  const ready = !confirmText || fold(typed) === fold(confirmText);
  const close = useCallback(() => {
    if (!busy) onClose();
  }, [busy, onClose]);

  async function confirm() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
    } catch (e) {
      setError(friendlyError(e));
      setBusy(false);
    }
  }

  return (
    <Modal title={title} subtitle={subtitle} icon={icon} tone={danger ? "danger" : undefined} onClose={close}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void confirm();
        }}
      >
        {children}
        {confirmText && (
          <div className="field">
            <label htmlFor={typedId}>Type {confirmText} to confirm</label>
            <input id={typedId} className="input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />
          </div>
        )}
        <ErrorText error={error} />
        <SheetActions
          quiet={
            // Cancel gets the initial focus: a stray Enter must never confirm a destructive action.
            <button type="button" className="btn btn-text" onClick={close} disabled={busy} data-autofocus={danger && !confirmText ? "" : undefined}>
              {cancel}
            </button>
          }
        >
          <button type="submit" className={`btn btn-block ${danger ? "btn-danger-solid" : "btn-primary"}`} disabled={busy || !ready} data-autofocus={danger ? undefined : ""}>
            {busy ? busyAction : action}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

export function ErrorText({ error }: { error: string | null }) {
  return error ? (
    <div className="alert alert-error" role="alert">
      {error}
    </div>
  ) : null;
}
