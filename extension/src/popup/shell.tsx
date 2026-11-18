/** Popup page frame: header with title and actions, scrolling body, optional footer. */

import { LogoMark } from "@web/components/Logo";
import { Icon } from "@web/components/ui";
import { type ReactNode, type Ref, useEffect, useId, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import type { PopupState, Status } from "../shared/types";
import { openCentered, POPUP_WINDOW } from "../shared/windows";

export function Page({
  title,
  onBack,
  brand,
  actions,
  footer,
  bodyRef,
  onScroll,
  children,
}: {
  title: string;
  onBack?: () => void;
  /** Show the PassAuth mark before the title (top-level pages). */
  brand?: boolean;
  actions?: ReactNode;
  footer?: ReactNode;
  /** The scrolling body (the list keeps and restores its position). */
  bodyRef?: Ref<HTMLElement>;
  onScroll?: () => void;
  children: ReactNode;
}) {
  return (
    <>
      <header className="pg-head">
        {onBack ? (
          <button type="button" className="btn btn-icon" aria-label="Back" title="Back" onClick={onBack}>
            <Icon name="back" />
          </button>
        ) : brand ? (
          <LogoMark size={24} />
        ) : null}
        <h1 className="grow">{title}</h1>
        {actions}
      </header>
      <main className="pg-body" ref={bodyRef} onScroll={onScroll}>
        {children}
      </main>
      {footer && <footer className="pg-foot">{footer}</footer>}
    </>
  );
}

/**
 * A button that opens a small menu; closes on outside click, Escape, or choosing an item. After a choice the focus
 * goes back to the button (so a dialog the choice opens returns it there too).
 */
export function Menu({
  label,
  trigger,
  className = "btn btn-icon",
  tabIndex,
  children,
}: {
  label: string;
  trigger: ReactNode;
  className?: string;
  /** For rows with a roving tab stop: -1 keeps the button out of the Tab order. */
  tabIndex?: number;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [up, setUp] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const id = useId();
  const items = () => [...(listRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])];
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs when the menu opens or closes; `items` only reads the DOM
  useEffect(() => {
    if (!open) return;
    // Menu keyboard pattern: focus the first item, arrows/Home/End move, Escape returns to the button.
    items()[0]?.focus();
    const onPointer = (e: Event) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      const list = items();
      const i = list.indexOf(document.activeElement as HTMLButtonElement);
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        list[(i + (e.key === "ArrowDown" ? 1 : list.length - 1)) % list.length]?.focus();
      } else if (e.key === "Home") list[0]?.focus();
      else if (e.key === "End") list.at(-1)?.focus();
      else if (e.key === "Tab") setOpen(false);
      else return;
      if (e.key !== "Tab") e.preventDefault();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button
        type="button"
        ref={triggerRef}
        className={className}
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={id}
        tabIndex={tabIndex}
        onClick={(e) => {
          // Open upwards when there's no room below (rows near the bottom of the list).
          setUp(e.currentTarget.getBoundingClientRect().bottom > innerHeight - 200);
          setOpen(!open);
        }}
      >
        {trigger}
      </button>
      {open && (
        // biome-ignore lint/a11y/useKeyWithClickEvents: choosing an item (a button: click or Enter) closes the menu; Escape is handled above
        <div
          id={id}
          ref={listRef}
          className={`menu${up ? " up" : ""}`}
          role="menu"
          aria-label={label}
          onClick={() => {
            // The item's own handler ran first: focus goes back to the button before the menu closes.
            triggerRef.current?.focus();
            setOpen(false);
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

export function MenuItem({ icon, children, onClick, danger }: { icon?: Parameters<typeof Icon>[0]["name"]; children: ReactNode; onClick: () => void; danger?: boolean }) {
  return (
    <button type="button" role="menuitem" className={danger ? "danger" : undefined} onClick={onClick}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  );
}

/** Whether this page is the pop-out window (not the toolbar popup). */
export const isPopOut = () => new URLSearchParams(location.search).has("popout");

/** Open PassAuth in its own window, where the popup was (its view is restored), and close this popup. */
export async function openPopOut() {
  // Over the browser window this popup belongs to, not in a corner of the screen.
  const browser = await chrome.windows.getCurrent().catch(() => null);
  await openCentered(chrome.runtime.getURL("popup.html?popout=1"), POPUP_WINDOW, { windowId: browser?.id });
  window.close();
}

/** Open the popup in its own window so it stays open while you work in a page. */
export function PopOut() {
  if (isPopOut()) return null;
  return (
    <button type="button" className="btn btn-icon" aria-label="Open in a window" title="Open in a window" onClick={openPopOut}>
      <Icon name="external" />
    </button>
  );
}

/** Initials from the profile name ("Fahed Alhammadi" → "FA"), else from the email. */
export function initials(name: string, email: string) {
  const words = name.trim().split(/\s+/).filter(Boolean);
  const [first, second] = words;
  if (first && second) return (first.charAt(0) + (words.at(-1) ?? second).charAt(0)).toUpperCase();
  if (first) return first.slice(0, 2).toUpperCase();
  const [p1, p2] = (email.split("@")[0] ?? "").split(/[._-]+/).filter(Boolean);
  return ((p1 && p2 ? p1.charAt(0) + p2.charAt(0) : p1?.slice(0, 2)) || "?").toUpperCase();
}

/** An account's profile picture (decorative: the name next to it is the label), else its initials. */
export function AccountPicture({ name, email, avatar }: { name: string; email: string; avatar?: string }) {
  return avatar ? <img className="account-pic" src={avatar} alt="" /> : initials(name, email);
}

const STATUS_LABEL: Record<Status, string> = { unlocked: "Unlocked", locked: "Locked", "logged-out": "Signed out", setup: "" };

/** Account menu: who is signed in, other accounts to switch to, add account, lock, web vault, sign out (asks first: `onSignOut`). */
export function Account({ state, onChange, onSignOut }: { state: PopupState; onChange: () => void; onSignOut: () => void }) {
  const others = state.accounts.filter((a) => a.id !== state.activeId);
  return (
    <Menu
      label="Accounts"
      className="avatar-btn"
      trigger={
        <span aria-hidden="true" className="avatar-face">
          <AccountPicture name={state.name} email={state.email} avatar={state.avatar} />
        </span>
      }
    >
      <div className="menu-head">
        <span className="title">{state.name || state.email}</span>
        {state.name && <span className="sub">{state.email}</span>}
        <span className="sub">{new URL(state.server).host}</span>
      </div>
      {others.map((a) => (
        <button type="button" key={a.id} role="menuitem" className="account-item" onClick={() => callPopup("account:switch", { id: a.id }).then(onChange)}>
          <span className="avatar-sm" aria-hidden="true">
            <AccountPicture name={a.name} email={a.email} avatar={a.avatar} />
          </span>
          <span className="grow">
            <span className="title">{a.name || a.email}</span>
            <span className="sub">{new URL(a.server).host}</span>
          </span>
          <span className="state">{STATUS_LABEL[a.status]}</span>
        </button>
      ))}
      {state.accounts.length < 5 && (
        <MenuItem icon="plus" onClick={() => callPopup("account:add").then(onChange)}>
          Add account
        </MenuItem>
      )}
      <hr />
      <MenuItem icon="lock" onClick={() => callPopup("lock").then(onChange)}>
        {state.accounts.length > 1 ? "Lock all" : "Lock"}
      </MenuItem>
      <MenuItem icon="external" onClick={() => chrome.tabs.create({ url: state.server })}>
        Open web vault
      </MenuItem>
      <MenuItem icon="logout" danger onClick={onSignOut}>
        Sign out…
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
      <span id="other-accounts">{adding ? "Go back to" : "Switch account"}</span>
      {/* biome-ignore lint/a11y/useSemanticElements: styled like the choice cards elsewhere; a fieldset would bring its own border and spacing */}
      <div className="choices" role="group" aria-labelledby="other-accounts">
        {others.map((a) => (
          <button
            key={a.id}
            type="button"
            className="choice"
            onClick={() => (adding ? callPopup("account:cancelAdd") : callPopup("account:switch", { id: a.id })).then(() => (adding ? callPopup("account:switch", { id: a.id }) : null)).then(onChange)}
          >
            <span className="tile avatar-round" aria-hidden="true">
              <AccountPicture name={a.name} email={a.email} avatar={a.avatar} />
            </span>
            <span className="choice-text">
              <span className="choice-title">{a.name || a.email}</span>
              <span className="choice-sub">{new URL(a.server).host}</span>
            </span>
            <span className="choice-trail">{STATUS_LABEL[a.status]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

/**
 * Countdown for a verification code, drawn in the shield gradient (the shared `--ring-*` tokens, so it follows the
 * theme). The number is for the eye; screen readers get "N seconds left" as text.
 */
export function Ring({ remaining, period }: { remaining: number; period: number }) {
  const r = 10;
  const c = 2 * Math.PI * r;
  const id = useId().replace(/:/g, "");
  return (
    <span className={`ring${remaining <= 5 ? " low" : ""}`}>
      <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
        <defs>
          <linearGradient id={id} x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" style={{ stopColor: "var(--ring-1)" }} />
            <stop offset="0.55" style={{ stopColor: "var(--ring-2)" }} />
            <stop offset="1" style={{ stopColor: "var(--ring-3)" }} />
          </linearGradient>
        </defs>
        <circle className="track" cx="14" cy="14" r={r} />
        <circle className="arc" cx="14" cy="14" r={r} stroke={`url(#${id})`} strokeDasharray={c} strokeDashoffset={c * (1 - remaining / period)} />
      </svg>
      <span className="n" aria-hidden="true">
        {remaining}
      </span>
      <span className="sr-only">{remaining} seconds left</span>
    </span>
  );
}
