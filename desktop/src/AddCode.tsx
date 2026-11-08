/**
 * otpauth:// and apple-otpauth:// links (two-step login QR codes, "Set Up Codes In" on macOS): pick the
 * login the verification code belongs to, then the web vault's item editor opens with it filled in.
 * The key waits in memory until the vault is unlocked; nothing is saved until the user saves.
 */
import { useDeferredValue, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { Icon, Modal, SiteIcon, toast } from "@web/components/ui";
import { clearDraft, hasUnsavedEdit, openDraft } from "@web/lib/drafts";
import { useShowIcons } from "@web/lib/prefs";
import { siteHost, type VaultEntry } from "@web/lib/types";
import { useVault } from "@web/lib/vault";
import { navigateTo } from "./bridge";
import { otpLabel, parseOtpLink, type OtpKey } from "./otpauth";

const SCHEMES = ["otpauth:", "apple-otpauth:"];

type Pending = { key: OtpKey; seq: number };
let pending: Pending | null = null;
let seq = 0;
/** A problem with a link that arrived before the toasts could show (cold start). */
let problem: string | null = null;
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((fn) => fn());

function handleLinks(urls: string[]) {
  const link = urls.filter((u) => SCHEMES.some((s) => u.toLowerCase().startsWith(s))).pop();
  if (!link) return;
  const parsed = parseOtpLink(link);
  if ("problem" in parsed) {
    problem = parsed.problem;
  } else {
    pending = { key: parsed.key, seq: ++seq };
  }
  notify();
}

/** Links that started the app and links that arrive while it runs. Call once the wasm module is loaded. */
export async function installOtpLinks() {
  let received = false;
  await onOpenUrl((urls) => {
    received = true;
    handleLinks(urls);
  });
  // Started by a link: unless the event above already delivered it.
  const current = await getCurrent().catch(() => null);
  if (!received && current) handleLinks(current);
}

function usePending() {
  return useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => pending,
  );
}
const useProblem = () =>
  useSyncExternalStore(
    (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    () => problem,
  );

/** Rendered with the web vault: notices, and the login picker once the vault is unlocked. */
export function AddCodeHost() {
  const current = usePending();
  const bad = useProblem();
  const { status } = useVault();
  const toldLocked = useRef(0);

  useEffect(() => {
    if (!bad) return;
    toast(bad);
    problem = null;
    notify();
  }, [bad]);

  // A prepared edit never outlives the unlocked session (lock, sign out, another account).
  useEffect(() => {
    if (status !== "unlocked") clearDraft();
  }, [status]);

  useEffect(() => {
    if (!current || toldLocked.current === current.seq) return;
    if (status === "locked" || status === "logged-out" || status === "unreachable") {
      toldLocked.current = current.seq;
      toast("Unlock PassAuth to save the verification code.");
    }
  }, [current, status]);

  if (!current || status !== "unlocked") return null;
  return <AddCodeDialog key={current.seq} otp={current.key} />;
}

function done() {
  pending = null;
  notify();
}

/** Logins first whose name or website mentions the issuer, then by name. */
function rankLogins(items: VaultEntry[], writable: Set<string>, issuer: string, query: string) {
  const iss = issuer.trim().toLowerCase();
  const q = query.trim().toLowerCase();
  const related = (e: VaultEntry) =>
    !!iss && (e.item.name.toLowerCase().includes(iss) || (e.item.login?.urls ?? []).some((u) => u.url.toLowerCase().includes(iss)));
  return items
    .filter((e) => !e.deletedAt && e.item.login && writable.has(e.vaultId))
    .filter(
      (e) =>
        !q ||
        e.item.name.toLowerCase().includes(q) ||
        e.item.login!.username.toLowerCase().includes(q) ||
        e.item.login!.urls.some((u) => u.url.toLowerCase().includes(q)),
    )
    .map((e) => ({ e, r: related(e) }))
    .sort((a, b) => (a.r !== b.r ? (a.r ? -1 : 1) : a.e.item.name.localeCompare(b.e.item.name, undefined, { sensitivity: "base" })))
    .map(({ e }) => e);
}

function AddCodeDialog({ otp }: { otp: OtpKey }) {
  const { items, vaults } = useVault();
  const showIcons = useShowIcons();
  const [query, setQuery] = useState("");
  const deferred = useDeferredValue(query);
  const writable = useMemo(() => new Set(vaults.filter((v) => v.role !== "read").map((v) => v.id)), [vaults]);
  const logins = useMemo(() => rankLogins(items, writable, otp.issuer, deferred), [items, writable, otp.issuer, deferred]);
  const label = otpLabel(otp);
  // Opening the editor replaces one with unsaved changes: ask first.
  const [replacing, setReplacing] = useState<{ entry: VaultEntry | null } | null>(null);

  const choose = (entry: VaultEntry | null, force = false) => {
    if (!force && hasUnsavedEdit()) return setReplacing({ entry });
    done();
    navigateTo(`/vault/all/${entry ? entry.id : "new-login"}`);
    openDraft(entry ? entry.id : "new-login", (item) => ({
      ...item,
      name: entry ? item.name : otp.issuer || item.name,
      login: item.login && { ...item.login, totp: otp.value, username: entry ? item.login.username : otp.account },
    }));
  };

  if (replacing) {
    return (
      <Modal key="discard" title="Discard your changes?" onClose={() => setReplacing(null)}>
        <p className="card-text">The item you're editing has changes you haven't saved. Adding the verification code opens another editor and discards them.</p>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={() => setReplacing(null)} data-autofocus="">
            Go back
          </button>
          <button type="button" className="btn btn-primary" onClick={() => choose(replacing.entry, true)}>
            Discard changes
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal key="pick" title="Add verification code" onClose={done}>
      <p className="card-text">{label ? `Choose the login for ${label}.` : "Choose the login this verification code belongs to."}</p>
      <div className="input-group">
        <span className="row" style={{ paddingLeft: 10, color: "var(--ink-3)" }}>
          <Icon name="search" />
        </span>
        <input className="input" type="search" placeholder="Search logins" aria-label="Search logins" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <button type="button" className="btn" style={{ justifyContent: "flex-start" }} onClick={() => choose(null)}>
        <Icon name="plus" /> New login
      </button>
      <div className="list add-code-list" role="list" aria-label="Logins">
        {logins.length === 0 ? (
          <p className="empty">{query ? `No logins match "${query}".` : "No logins yet."}</p>
        ) : (
          logins.map((e) => (
            <div role="listitem" key={e.id}>
              <button type="button" className="list-item" onClick={() => choose(e)}>
                <SiteIcon host={siteHost(e.item)} name={e.item.name} enabled={showIcons} />
                <span className="grow">
                  <span className="title" style={{ display: "block" }}>
                    {e.item.name || "Untitled"}
                  </span>
                  <span className="sub" style={{ display: "block" }}>
                    {e.item.login?.username || siteHost(e.item)}
                  </span>
                </span>
                {e.item.login?.totp && <span className="muted small">Has a code</span>}
              </button>
            </div>
          ))
        )}
      </div>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn" onClick={done}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
