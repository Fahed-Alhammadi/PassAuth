/**
 * Password health: the "Duplicate logins" section and its "Combine" preview (ARCHITECTURE "Duplicate logins"). The
 * grouping and merging rules are in `lib/duplicates.ts`; the writes are the vault's own `updateItem` and `trashItem`.
 */
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useNavigate } from "react-router";
import { Icon, Modal, SheetActions, SiteIcon, toast } from "../components/ui";
import { friendlyError } from "../lib/api";
import {
  combineGroup,
  CombineIncomplete,
  findDuplicates,
  groupKey,
  joinNames,
  mergeGroup,
  PICK_TOTP,
  type DuplicateGroup,
} from "../lib/duplicates";
import { server } from "../lib/server";
import { useSiteIconsShown } from "../lib/site-icons";
import type { VaultEntry } from "../lib/types";
import { baseDomain } from "../wasm/passauth_core";
import { getBundle, getState, totpCode, trashItem, updateItem, useVault } from "../lib/vault";
import type { HealthLinkState } from "./Health";
import { filterPath } from "./Shell";
import "../styles/duplicates.css";

type Group = DuplicateGroup<VaultEntry>;

const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const letter = (n: number) => LETTERS[n] ?? String(n + 1);
const nameOf = (e: VaultEntry) => e.item.name || "Untitled";
const firstUrl = (e: VaultEntry) => e.item.login?.urls.find((u) => u.url.trim())?.url ?? "";

// --------------------------------------------------------- kept separate

/** "Keep separate" is remembered on this device, per server and account: the sorted id lists of the groups. */
function keptStorageKey(): string | null {
  const account = getBundle()?.account_id;
  return account ? `pa.duplicates-kept.${server.origin()}|${account}` : null;
}

function readKept(): Set<string> {
  const key = keptStorageKey();
  if (!key) return new Set();
  try {
    const raw = JSON.parse(localStorage.getItem(key) ?? "[]") as unknown;
    return new Set(Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : []);
  } catch {
    return new Set();
  }
}

function writeKept(kept: Set<string>, live: readonly string[]) {
  const key = keptStorageKey();
  if (!key) return;
  // Only groups that still exist are kept in the list, so it never grows past the vault.
  const list = [...kept].filter((k) => live.includes(k)).sort();
  try {
    if (list.length) localStorage.setItem(key, JSON.stringify(list));
    else localStorage.removeItem(key);
  } catch {
    // Storage blocked: the choice lasts for this page session only.
  }
}

// ----------------------------------------------------------------- online

function useOnline(): boolean {
  const [online, setOnline] = useState(() => navigator.onLine);
  useEffect(() => {
    const on = () => setOnline(true);
    const off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
    };
  }, []);
  return online;
}

// ---------------------------------------------------------------- section

/** The groups of duplicate logins in the vaults the user can write to now. */
function useDuplicateGroups(): Group[] {
  const { items, vaults, offlineChanges, deviceRecordUnreadable } = useVault();
  return useMemo(() => {
    const writable = new Set(vaults.filter((v) => v.role !== "read" && !v.manifestWarning && !deviceRecordUnreadable).map((v) => v.id));
    const pending = new Set(offlineChanges.map((c) => c.item_id));
    return findDuplicates(items, { baseDomain, writableVault: (id) => writable.has(id), pending });
  }, [items, vaults, offlineChanges, deviceRecordUnreadable]);
}

/** What combining adds that not every login has: a 2FA code, passkeys. */
function gains(group: Group): string[] {
  const out: string[] = [];
  const logins = group.entries.map((e) => e.item.login);
  if (!group.differentTotp && group.totps.length && logins.some((l) => !l?.totp?.trim())) out.push("Adds 2FA code");
  const all = new Set(logins.flatMap((l) => (l?.passkeys ?? []).map((p) => p.credential_id)));
  const missing = [...all].filter((id) => logins.some((l) => !l?.passkeys.some((p) => p.credential_id === id))).length;
  if (missing) out.push(`Adds ${missing === 1 ? "1 passkey" : `${missing} passkeys`}`);
  return out;
}

export function DuplicatesSection() {
  const groups = useDuplicateGroups();
  const showIcons = useSiteIconsShown();
  const online = useOnline();
  const navigate = useNavigate();
  const heading = useRef<HTMLHeadingElement>(null);
  const [kept, setKept] = useState(readKept);
  const [showKept, setShowKept] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  const keys = groups.map(groupKey);
  const visible = groups.filter((g) => !kept.has(groupKey(g)));
  const hidden = groups.filter((g) => kept.has(groupKey(g)));
  const openGroup = groups.find((g) => groupKey(g) === open) ?? null;

  const setKeptTo = (next: Set<string>) => {
    setKept(next);
    writeKept(next, keys);
  };

  function done(group: Group) {
    setOpen(null);
    setProblem(null);
    const trashed = joinNames(group.entries.slice(1).map(nameOf));
    const id = group.keeper.id;
    toast(`Logins combined. ${trashed} ${group.entries.length > 2 ? "are" : "is"} in the trash.`, {
      label: "Open combined login",
      run: () => navigate(`${filterPath("all")}/${id}`, { state: { from: "/health", edit: false } satisfies HealthLinkState }),
    });
    heading.current?.focus();
  }

  function failed(message: string) {
    setOpen(null);
    setProblem(message);
    heading.current?.focus();
  }

  return (
    <section className="card dup-section" aria-labelledby="health-duplicates">
      <div className="card-head">
        <div className="card-title">
          <h2 id="health-duplicates" ref={heading} tabIndex={-1}>
            Duplicate logins
          </h2>
          {visible.length > 0 && <span className="badge">{visible.length}</span>}
        </div>
      </div>
      <p className="card-text">Same site, same user name and same password. Combining keeps everything from each login.</p>

      {problem && (
        <div className="alert alert-error" role="alert">
          {problem}
        </div>
      )}
      {!online && visible.length > 0 && <p className="small muted">You're offline. Combining logins needs a connection to your server.</p>}

      {visible.length === 0 ? (
        <div className="health-clear">
          <span className="tile tile-ok" aria-hidden="true">
            <Icon name="check" />
          </span>
          <span className="grow">
            <span className="row-title">No duplicate logins</span>
            <span className="row-sub">A login shows here only when the site, user name and password all match another one.</span>
          </span>
        </div>
      ) : (
        <ul className="dup-list" aria-labelledby="health-duplicates">
          {visible.map((g) => (
            <GroupRow
              key={groupKey(g)}
              group={g}
              showIcons={showIcons}
              online={online}
              onCombine={() => {
                setProblem(null);
                setOpen(groupKey(g));
              }}
              onKeep={() => setKeptTo(new Set([...kept, groupKey(g)]))}
            />
          ))}
        </ul>
      )}

      {hidden.length > 0 && (
        <div className="dup-kept">
          <button type="button" className="btn btn-text" aria-expanded={showKept} onClick={() => setShowKept((s) => !s)}>
            {showKept ? "Hide kept separate" : `Show ${hidden.length} kept separate`}
          </button>
          {showKept && (
            <ul className="dup-list">
              {hidden.map((g) => (
                <GroupRow
                  key={groupKey(g)}
                  group={g}
                  showIcons={showIcons}
                  online={online}
                  kept
                  onCombine={() => setOpen(groupKey(g))}
                  onKeep={() => {
                    const next = new Set(kept);
                    next.delete(groupKey(g));
                    setKeptTo(next);
                  }}
                />
              ))}
            </ul>
          )}
        </div>
      )}

      {openGroup && <CombineDialog group={openGroup} online={online} onClose={() => setOpen(null)} onDone={done} onFailed={failed} />}
    </section>
  );
}

function GroupRow({
  group,
  showIcons,
  online,
  kept = false,
  onCombine,
  onKeep,
}: {
  group: Group;
  showIcons: boolean;
  online: boolean;
  kept?: boolean;
  onCombine: () => void;
  onKeep: () => void;
}) {
  const names = joinNames(group.entries.map(nameOf));
  const chips = gains(group);
  return (
    <li className="dup-row">
      <SiteIcon host={group.site} name={group.site} enabled={showIcons} />
      <div className="dup-row-text">
        <span className="dup-row-site" title={group.site}>
          {group.site}
        </span>
        {group.username && (
          <span className="dup-row-user" title={group.username}>
            {group.username}
          </span>
        )}
        <span className="dup-row-names" title={names}>
          {names}
        </span>
        {(chips.length > 0 || group.differentTotp) && (
          <span className="dup-chips">
            {group.differentTotp && <span className="dup-chip dup-chip-attn">Different 2FA codes</span>}
            {chips.map((c) => (
              <span key={c} className="dup-chip">
                {c}
              </span>
            ))}
          </span>
        )}
      </div>
      <div className="dup-row-actions">
        <button type="button" className="btn btn-primary" onClick={onCombine} disabled={!online} aria-label={`Combine ${names}`}>
          Combine…
        </button>
        <button type="button" className="btn btn-text" onClick={onKeep}>
          {kept ? "Show again" : "Keep separate"}
        </button>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------- preview

/** Source markers: the letters of the logins a value comes from. */
function Markers({ of, group }: { of: readonly string[]; group: Group }) {
  return (
    <span className="dup-markers">
      {group.entries.map((e, n) =>
        of.includes(e.id) ? (
          <span key={e.id} className={`dup-marker dup-m${n % 4}`} role="img" aria-label={`from ${nameOf(e)}`} title={`From ${nameOf(e)}`}>
            {letter(n)}
          </span>
        ) : null,
      )}
    </span>
  );
}

/** The live code of a 2FA secret with a small countdown ring. */
function LiveCode({ secret, now }: { secret: string; now: number }) {
  let code: { code: string; remaining: number; period: number };
  try {
    code = totpCode(secret, now);
  } catch {
    return <span className="small muted">Invalid authenticator key</span>;
  }
  const r = 7;
  const c = 2 * Math.PI * r;
  const pretty = code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code;
  return (
    <span className="dup-code">
      <svg className={`totp-ring${code.remaining <= 5 ? " low" : ""}`} width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
        <circle className="track" cx="9" cy="9" r={r} style={{ strokeWidth: 2.5 }} />
        <circle className="arc" cx="9" cy="9" r={r} strokeDasharray={c} strokeDashoffset={c * (1 - code.remaining / code.period)} style={{ strokeWidth: 2.5 }} />
      </svg>
      <span className="dup-code-digits">{pretty}</span>
      <span className="sr-only">{`, ${code.remaining} seconds left`}</span>
    </span>
  );
}

const LONG_NOTES = 240;

function CombineDialog({
  group,
  online,
  onClose,
  onDone,
  onFailed,
}: {
  group: Group;
  online: boolean;
  onClose: () => void;
  onDone: (group: Group) => void;
  onFailed: (message: string) => void;
}) {
  const [name, setName] = useState(group.keeper.item.name);
  const [totp, setTotp] = useState<string | null>(null);
  const [step, setStep] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);
  // The group as it was when the preview opened: the combine checks nothing changed since.
  const [frozen] = useState(group);

  useEffect(() => {
    if (!frozen.differentTotp) return;
    const t = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(t);
  }, [frozen.differentTotp]);

  const entries = frozen.entries;
  const needsTotp = frozen.differentTotp && totp === null;
  const merged = useMemo(() => {
    try {
      return mergeGroup(frozen, { name, totp: frozen.differentTotp ? (totp ?? frozen.totps[0].secret) : undefined });
    } catch {
      return null;
    }
  }, [frozen, name, totp]);
  const login = merged?.login;
  const has = (pred: (e: VaultEntry) => boolean) => entries.filter(pred).map((e) => e.id);
  const others = entries.slice(1);
  const trashNames = joinNames(others.map((e) => `${nameOf(e)} (${letter(entries.indexOf(e))})`));
  const names = [...new Set(entries.map((e) => e.item.name))];
  const busy = step !== null;
  let rowIndex = 0;
  const row = (): CSSProperties => ({ "--i": rowIndex++ }) as CSSProperties;

  async function combine() {
    if (!merged || needsTotp || busy) return;
    try {
      const final = mergeGroup(frozen, { name, totp: frozen.differentTotp ? totp : undefined });
      await combineGroup(frozen, final, {
        update: (entry, item) => updateItem(entry, item),
        trash: (id) => trashItem(id),
        current: (id) => getState().items.find((e) => e.id === id),
        waiting: (id) => getState().offlineChanges.some((c) => c.item_id === id),
        progress: (s) =>
          setStep(s.kind === "save" ? "Saving combined login…" : `Moving ${s.left === 1 ? "1 login" : `${s.left} logins`} to the trash…`),
      });
      onDone(frozen);
    } catch (e) {
      setStep(null);
      if (e instanceof CombineIncomplete) onFailed(e.message);
      else onFailed(friendlyError(e));
    }
  }

  return (
    <Modal
      title={`Combine ${entries.length} logins`}
      subtitle={frozen.username ? `${frozen.site}, ${frozen.username}` : frozen.site}
      icon={<SiteIcon host={frozen.site} name={frozen.site} />}
      onClose={() => !busy && onClose()}
    >
      <form
        className="dup-preview"
        onSubmit={(e) => {
          e.preventDefault();
          void combine();
        }}
      >
        <ul className="dup-sources" aria-label="Logins to combine">
          {entries.map((e, n) => (
            <li key={e.id} className="dup-source">
              <span className={`dup-marker dup-m${n % 4}`} aria-hidden="true">
                {letter(n)}
              </span>
              <span className="dup-source-text">
                <span className="dup-source-name" title={nameOf(e)}>
                  {nameOf(e)}
                </span>
                <span className="dup-source-url" title={firstUrl(e)}>
                  {firstUrl(e)}
                </span>
              </span>
            </li>
          ))}
        </ul>

        <div className="dup-result">
          <h3 className="dup-result-title">Combined login</h3>

          <fieldset className="dup-field" style={row()} disabled={busy}>
            <legend className="dup-label">Name</legend>
            <div className="choices choices-compact">
              {names.map((n) => (
                <label key={n} className="choice">
                  <input type="radio" name="dup-name" checked={name === n} onChange={() => setName(n)} />
                  <span className="choice-text">
                    <span className="choice-title">{n || "Untitled"}</span>
                  </span>
                  <Markers of={has((e) => e.item.name === n)} group={frozen} />
                </label>
              ))}
            </div>
          </fieldset>

          <div className="dup-field" style={row()}>
            <span className="dup-label">Web addresses</span>
            <ul className="dup-values">
              {(login?.urls ?? []).map((u) => (
                <li key={`${u.url}\u0000${u.match}`} className="dup-value">
                  <span className="dup-value-text" title={u.url}>
                    {u.url}
                    {u.match !== "default" && <span className="muted">{` (${u.match.replace("_", " ")} match)`}</span>}
                  </span>
                  <Markers of={has((e) => !!e.item.login?.urls.some((x) => x.url === u.url && x.match === u.match))} group={frozen} />
                </li>
              ))}
            </ul>
            <p className="dup-hint">Autofill works on all of these.</p>
          </div>

          {frozen.totps.length > 0 && (
            <div className="dup-field" style={row()}>
              {frozen.differentTotp ? (
                <fieldset className="dup-field" disabled={busy}>
                  <legend className="dup-label">2FA code</legend>
                  <div className="choices choices-compact" role="radiogroup" aria-required="true" aria-describedby="dup-totp-hint">
                    {frozen.totps.map((t) => (
                      <label key={t.secret} className="choice">
                        <input type="radio" name="dup-totp" required checked={totp === t.secret} onChange={() => setTotp(t.secret)} />
                        <span className="choice-text">
                          <span className="choice-title">{t.label}</span>
                          <LiveCode secret={t.secret} now={now} />
                        </span>
                        <Markers of={t.from} group={frozen} />
                      </label>
                    ))}
                  </div>
                  <p id="dup-totp-hint" className={needsTotp ? "dup-hint dup-hint-attn" : "dup-hint"}>
                    {PICK_TOTP}
                    {needsTotp && " Combine stays off until you choose one."}
                  </p>
                </fieldset>
              ) : (
                <>
                  <span className="dup-label">2FA code</span>
                  <div className="dup-value dup-from">
                    <span>From</span>
                    <Markers of={frozen.totps[0].from} group={frozen} />
                  </div>
                </>
              )}
            </div>
          )}

          {(login?.passkeys.length ?? 0) > 0 && (
            <div className="dup-field" style={row()}>
              <span className="dup-label">{login?.passkeys.length === 1 ? "1 passkey" : `${login?.passkeys.length} passkeys`}</span>
              <ul className="dup-values">
                {login?.passkeys.map((p) => (
                  <li key={p.credential_id} className="dup-value">
                    <span className="dup-value-text">
                      <span title={p.rp_id}>{p.rp_id}</span>
                      {p.user_name && <span className="dup-value-sub" title={p.user_name}>{p.user_name}</span>}
                    </span>
                    <Markers of={has((e) => !!e.item.login?.passkeys.some((x) => x.credential_id === p.credential_id))} group={frozen} />
                  </li>
                ))}
              </ul>
            </div>
          )}

          {merged?.notes && (
            <div className="dup-field" style={row()}>
              <span className="dup-label">Notes</span>
              {merged.notes.length > LONG_NOTES ? (
                <details className="dup-notes">
                  <summary>
                    <span className="dup-notes-peek">{merged.notes.slice(0, 120)}…</span>
                    <span className="dup-notes-more">Show all</span>
                  </summary>
                  <p className="dup-notes-text">{merged.notes}</p>
                </details>
              ) : (
                <p className="dup-notes-text">{merged.notes}</p>
              )}
              <Markers of={has((e) => !!e.item.notes?.trim())} group={frozen} />
            </div>
          )}

          {(merged?.password_history.length ?? 0) > 0 && (
            <div className="dup-field" style={row()}>
              <span className="dup-label">Password history</span>
              <p className="dup-value-text">
                {merged?.password_history.length === 1 ? "1 earlier password kept" : `${merged?.password_history.length} earlier passwords kept`}
              </p>
            </div>
          )}

          {(merged?.tags.length ?? 0) > 0 && (
            <div className="dup-field" style={row()}>
              <span className="dup-label">Tags</span>
              <span className="dup-chips">
                {merged?.tags.map((t) => (
                  <span key={t} className="dup-chip">
                    {t}
                  </span>
                ))}
              </span>
            </div>
          )}
        </div>

        <p className="dup-footer">
          {trashNames} will move to the trash. You can restore {others.length === 1 ? "it" : "them"} from the trash.
        </p>
        {!online && <p className="small muted">You're offline. Combining logins needs a connection to your server.</p>}
        <p className="sr-only" role="status">
          {step ?? ""}
        </p>
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-block btn-primary" disabled={busy || needsTotp || !online || !merged} data-autofocus={needsTotp ? undefined : ""}>
            {step ?? "Combine logins"}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}
