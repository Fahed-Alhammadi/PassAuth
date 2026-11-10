/**
 * otpauth:// and apple-otpauth:// links (two-step login QR codes, "Set Up Codes In" on macOS): pick the
 * login the verification code belongs to, then the web vault's item editor opens with it filled in.
 * The key waits in memory until the vault is unlocked; nothing is saved until the user saves.
 */
import { useDeferredValue, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { ConfirmDialog, Icon, Modal, SheetActions, SiteIcon, toast } from "@web/components/ui";
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
      <ConfirmDialog
        key="discard"
        title="Discard your changes?"
        subtitle="The item you're editing has unsaved changes"
        icon="edit"
        action="Discard changes"
        cancel="Go back"
        onClose={() => setReplacing(null)}
        onConfirm={() => choose(replacing.entry, true)}
      >
        <p className="card-text">Adding the verification code opens another editor and discards them.</p>
      </ConfirmDialog>
    );
  }

  return (
    <Modal key="pick" title="Add verification code" subtitle={label ? `For ${label}` : "Choose the login it belongs to"} icon="shield" onClose={done}>
      <div className="input-group">
        <span className="input-lead">
          <Icon name="search" />
        </span>
        <input className="input" type="search" placeholder="Search logins" aria-label="Search logins" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <div className="choices choices-scroll add-code-list" role="list" aria-label="Logins">
        <div role="listitem">
          <button type="button" className="choice" onClick={() => choose(null)}>
            <span className="tile" aria-hidden="true">
              <Icon name="plus" />
            </span>
            <span className="choice-text">
              <span className="choice-title">New login</span>
              <span className="choice-sub">{label ? `Create a login for ${label}` : "Create a login for this code"}</span>
            </span>
          </button>
        </div>
        {logins.map((e) => (
          <div role="listitem" key={e.id}>
            <button type="button" className="choice" onClick={() => choose(e)}>
              <SiteIcon host={siteHost(e.item)} name={e.item.name} enabled={showIcons} />
              <span className="choice-text">
                <span className="choice-title">{e.item.name || "Untitled"}</span>
                <span className="choice-sub">{e.item.login?.username || siteHost(e.item)}</span>
              </span>
              {e.item.login?.totp && <span className="choice-trail">Has a code</span>}
            </button>
          </div>
        ))}
      </div>
      {logins.length === 0 && <p className="small muted">{query ? `No logins match "${query}".` : "You have no logins yet."}</p>}
      <SheetActions
        quiet={
          <button type="button" className="btn btn-text" onClick={done}>
            Cancel
          </button>
        }
      />
    </Modal>
  );
}
