/** Popup page frame: header with title and actions, scrolling body, optional footer. */
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { LogoMark } from "@web/components/Logo";
import { Icon } from "@web/components/ui";
import { send, type PopupState, type Status } from "../shared/messages";

export function Page({
  title,
  onBack,
  brand,
  actions,
  footer,
  children,
}: {
  title: string;
  onBack?: () => void;
  /** Show the PassAuth mark before the title (top-level pages). */
  brand?: boolean;
  actions?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
}) {
  return (
    <>
      <header className="pg-head">
        {onBack ? (
          <button className="btn btn-icon" aria-label="Back" title="Back" onClick={onBack}>
            <Icon name="back" />
          </button>
        ) : brand ? (
          <LogoMark size={24} />
        ) : null}
        <h1 className="grow">{title}</h1>
        {actions}
      </header>
      <main className="pg-body">{children}</main>
      {footer && <footer className="pg-foot">{footer}</footer>}
    </>
  );
}

/** A button that opens a small menu; closes on outside click, Escape, or choosing an item. */
export function Menu({ label, trigger, className = "btn btn-icon", children }: { label: string; trigger: ReactNode; className?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [up, setUp] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button
        className={className}
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={id}
        onClick={(e) => {
          // Open upwards when there's no room below (rows near the bottom of the list).
          setUp(e.currentTarget.getBoundingClientRect().bottom > innerHeight - 200);
          setOpen(!open);
        }}
      >
        {trigger}
      </button>
      {open && (
        <div id={id} className={`menu${up ? " up" : ""}`} role="menu" onClick={() => setOpen(false)}>
          {children}
        </div>
      )}
    </div>
  );
}

export function MenuItem({ icon, children, onClick, danger }: { icon?: Parameters<typeof Icon>[0]["name"]; children: ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button role="menuitem" className={danger ? "danger" : undefined} onClick={onClick}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

/** Open the popup in its own window so it stays open while you work in a page. */
export function PopOut() {
  if (new URLSearchParams(location.search).has("popout")) return null;
  return (
    <button
      className="btn btn-icon"
      aria-label="Open in a window"
      title="Open in a window"
      onClick={async () => {
        await chrome.windows.create({ url: chrome.runtime.getURL("popup.html?popout=1"), type: "popup", width: 400, height: 640 });
        window.close();
      }}
    >
      <Icon name="external" />
    </button>
  );
}

/** Initials from the profile name ("Fahed Alhammadi" → "FA"), else from the email. */
export function initials(name: string, email: string) {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length > 1) return (words[0][0] + words[words.length - 1][0]).toUpperCase();
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  const parts = (email.split("@")[0] ?? "").split(/[._-]+/).filter(Boolean);
  return ((parts.length > 1 ? parts[0][0] + parts[1][0] : parts[0]?.slice(0, 2)) || "?").toUpperCase();
}

const STATUS_LABEL: Record<Status, string> = { unlocked: "Unlocked", locked: "Locked", "logged-out": "Logged out", setup: "" };

/** Account menu: who is signed in, other accounts to switch to, add account, lock, web vault, log out. */
export function Account({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const others = state.accounts.filter((a) => a.id !== state.activeId);
  return (
    <Menu label="Accounts" className="avatar-btn" trigger={<span aria-hidden="true">{initials(state.name, state.email)}</span>}>
      <div className="menu-head">
        <span className="title">{state.name || state.email}</span>
        {state.name && <span className="sub">{state.email}</span>}
        <span className="sub">{new URL(state.server).host}</span>
      </div>
      {others.map((a) => (
        <button key={a.id} role="menuitem" className="account-item" onClick={() => send({ type: "account:switch", id: a.id }).then(onChange)}>
          <span className="avatar-sm" aria-hidden="true">
            {initials(a.name, a.email)}
          </span>
          <span className="grow">
            <span className="title">{a.name || a.email}</span>
            <span className="sub">{new URL(a.server).host}</span>
          </span>
          <span className="state">{STATUS_LABEL[a.status]}</span>
        </button>
      ))}
      {state.accounts.length < 5 && (
        <MenuItem icon="plus" onClick={() => send({ type: "account:add" }).then(onChange)}>
          Add account
        </MenuItem>
      )}
      <hr />
      <MenuItem icon="lock" onClick={() => send({ type: "lock" }).then(onChange)}>
        Lock
      </MenuItem>
      <MenuItem icon="external" onClick={() => chrome.tabs.create({ url: state.server })}>
        Open web vault
      </MenuItem>
      <MenuItem icon="logout" danger onClick={() => send({ type: "logout" }).then(onChange)}>
        Log out
      </MenuItem>
    </Menu>
  );
}

/**
 * On the setup, sign-in and unlock screens: switch to another account, or
 * cancel adding one.
 */
export function OtherAccounts({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const others = state.accounts.filter((a) => a.id !== state.activeId);
  if (!others.length) return null;
  const adding = state.status === "setup" || (state.status === "logged-out" && !state.accounts.some((a) => a.id === state.activeId));
  return (
    <div className="other-accounts">
      <span className="small muted">{adding ? "Or go back to" : "Switch account"}</span>
      {others.map((a) => (
        <button
          key={a.id}
          type="button"
          className="account-item"
          onClick={() => send(adding ? { type: "account:cancelAdd" } : { type: "account:switch", id: a.id }).then(() => (adding ? send({ type: "account:switch", id: a.id }) : null)).then(onChange)}
        >
          <span className="avatar-sm" aria-hidden="true">
            {initials(a.name, a.email)}
          </span>
          <span className="grow">
            <span className="title">{a.name || a.email}</span>
            <span className="sub">{new URL(a.server).host}</span>
          </span>
          <span className="state">{STATUS_LABEL[a.status]}</span>
        </button>
      ))}
    </div>
  );
}

/** Countdown for a verification code, drawn in the PassAuth shield gradient. */
export function Ring({ remaining, period }: { remaining: number; period: number }) {
  const r = 10;
  const c = 2 * Math.PI * r;
  const id = useId().replace(/:/g, "");
  return (
    <span className={`ring${remaining <= 5 ? " low" : ""}`} aria-label={`${remaining} seconds left`}>
      <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
        <defs>
          <linearGradient id={id} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" stopColor="#0866ED" />
            <stop offset="1" stopColor="#23D5F4" />
          </linearGradient>
        </defs>
        <circle className="track" cx="14" cy="14" r={r} />
        <circle className="arc" cx="14" cy="14" r={r} stroke={`url(#${id})`} strokeDasharray={c} strokeDashoffset={c * (1 - remaining / period)} />
      </svg>
      <span className="n">{remaining}</span>
    </span>
  );
}
