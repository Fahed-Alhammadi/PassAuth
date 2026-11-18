/**
 * An item's page (title = the item's name; the star toggles favourite), its password history, and the pieces they
 * share: masked values with reveal, copy and large type; the verification code with its countdown; the item's files
 * (files.tsx).
 */

import { ConfirmDialog, Icon, SiteIcon } from "@web/components/ui";
import { type Item, KIND_LABEL, kindOf } from "@web/lib/types";
import { type ReactNode, useEffect, useState } from "react";
import { callPopup } from "../shared/protocol";
import { secondsLeft } from "../shared/totp";
import type { ItemData, TotpCode, VaultSigner } from "../shared/types";
import { LargeType, PasswordChars } from "./chars";
import { activeTab, type CopyRequest, type Ctx, formatDate, hostOf, msg, splitCode } from "./ctx";
import { Files } from "./files";
import { identityRows } from "./identity";
import { Page, PopOut, Ring } from "./shell";
import { GLYPH } from "./vault";

/** One labelled value with actions, inside a card. */
function Field({ label, children, actions }: { label: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="kv">
      <div className="grow">
        <div className="k">{label}</div>
        <div className="v">{children}</div>
      </div>
      {actions && <div className="acts">{actions}</div>}
    </div>
  );
}

function CopyBtn({ ctx, req, label }: { ctx: Ctx; req: CopyRequest; label: string }) {
  return (
    <button type="button" className="btn btn-icon" aria-label={`Copy ${label.toLowerCase()}`} title={`Copy ${label.toLowerCase()}`} onClick={() => void ctx.copy(req, label)}>
      <Icon name="copy" />
    </button>
  );
}

/** A hidden value: reveal (digits and symbols marked), large type for passwords, copy. */
function Secret({ ctx, label, value, copy, large }: { ctx: Ctx; label: string; value: string; copy?: CopyRequest; large?: string }) {
  const [show, setShow] = useState(false);
  const [big, setBig] = useState(false);
  return (
    <Field
      label={label}
      actions={
        <>
          <button type="button" className="btn btn-icon" aria-label={show ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} aria-pressed={show} onClick={() => setShow(!show)}>
            <Icon name={show ? "eyeOff" : "eye"} />
          </button>
          {large !== undefined && (
            <button type="button" className="btn btn-icon btn-large-type" aria-label={`Show ${label.toLowerCase()} in large type`} title="Large type" onClick={() => setBig(true)}>
              <span aria-hidden="true">Aa</span>
            </button>
          )}
          <CopyBtn ctx={ctx} req={copy ?? { text: value }} label={label} />
        </>
      }
    >
      <span className="mono">{show ? <PasswordChars value={value} /> : "••••••••"}</span>
      {big && <LargeType title={large || label} value={value} onClose={() => setBig(false)} />}
    </Field>
  );
}

function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="group">
      {title && (
        <h2 className="group-title">
          <span>{title}</span>
          {actions}
        </h2>
      )}
      <div className="card-box">{children}</div>
    </section>
  );
}

/** A verification code as the background made it; `expires`: when it changes (ms). */
type Code = Pick<TotpCode, "code" | "period" | "expires">;

/**
 * The item's current verification code, counted down here every second. A new
 * code is asked for only when the shown one expires, so an open item doesn't
 * talk to the background every second (and never counts as activity).
 */
function useTotp(id: string, enabled: boolean): (Code & { remaining: number }) | null {
  const [code, setCode] = useState<Code | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    let current: Code | null = null;
    let asking = false;
    const ask = () => {
      if (asking) return;
      asking = true;
      callPopup("totp", { id })
        .then(
          (c) => {
            if (!alive) return;
            current = c;
            setCode(c);
          },
          () => {},
        )
        .finally(() => (asking = false));
    };
    ask();
    const t = setInterval(() => {
      const at = Date.now();
      setNow(at);
      if (current && at >= current.expires) ask();
    }, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id, enabled]);
  if (!code) return null;
  return { ...code, remaining: Math.max(1, secondsLeft(code.expires, now)) };
}

/** Load one item (back to the list when it is gone). */
function useItem(id: string, ctx: Ctx) {
  const [data, setData] = useState<ItemData | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: loads once per item (ctx changes with every state reload)
  useEffect(() => {
    callPopup("item", { id }).then(setData, (e) => {
      ctx.notify(msg(e));
      ctx.go({ tab: "vault", page: "list" });
    });
  }, [id]);
  return [data, setData] as const;
}

/**
 * Who signed the vault's share (signed sharing). The display rule: the email pinned for them first, what the server
 * lists now only as "listed by your server as …", and "verified" only next to a pinned email, never a server's name.
 */
function SignerLine({ signer }: { signer: VaultSigner }) {
  return (
    <p className="small muted">
      {signer.pinned ? `Shared by ${signer.email}` : `Shared by ${signer.email || "someone"} (as your server lists them)`}
      {signer.deleted ? " (account deleted since)" : ""}
      {signer.pinned && signer.listedAs ? `, listed by your server as ${signer.listedAs}` : ""}, signed with fingerprint <span className="mono">{signer.fingerprint}</span>
      {signer.verified ? " (verified)." : ". Compare it with them to be sure the share is theirs."}
    </p>
  );
}

export function ItemPage({ id, ctx }: { id: string; ctx: Ctx }) {
  const [data, setData] = useItem(id, ctx);
  const [tabId, setTabId] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const back = () => ctx.go({ tab: "vault", page: "list" });

  useEffect(() => {
    activeTab()
      .then(async (tab) => {
        if (!tab?.id || !tab.url?.startsWith("http")) return;
        const r = await callPopup("items", { url: tab.url });
        if (r.suggested.some((s) => s.id === id)) setTabId(tab.id);
      })
      // No page to fill on, or locked meanwhile: the item shows without a Fill button.
      .catch(() => {});
  }, [id]);
  const code = useTotp(id, !!data?.item.login?.totp);

  const i = data?.item;
  const kind = i ? kindOf(i) : "login";
  const l = i?.login;
  const site = l?.urls.map((u) => u.url).find((u) => /^https?:\/\//i.test(u)) ?? "";

  async function toggleFavorite(item: Item) {
    const next = { ...item, favorite: !item.favorite };
    try {
      await callPopup("updateItem", { id, item: next });
      setData((d) => (d ? { ...d, item: next } : d));
      ctx.notify(next.favorite ? "Added to favorites." : "Removed from favorites.");
    } catch (e) {
      ctx.notify(msg(e));
    }
  }

  const canFill = tabId !== null && !!(l?.password || l?.username);
  // One filled button per page: "Fill on this page" when the item matches the site, else Edit.
  const footer = data?.canWrite ? (
    <>
      <button type="button" className={canFill ? "btn" : "btn btn-primary"} onClick={() => ctx.go({ tab: "vault", page: "edit", id })}>
        <Icon name="edit" /> Edit
      </button>
      <span className="grow" />
      <button type="button" className="btn btn-icon btn-quiet-danger" aria-label="Move to trash" title="Move to trash" onClick={() => setConfirmDelete(true)}>
        <Icon name="trash" />
      </button>
    </>
  ) : undefined;

  const [first, second] = code ? splitCode(code.code) : ["", ""];

  return (
    <Page
      title={i?.name || KIND_LABEL[kind]}
      onBack={back}
      actions={
        <>
          {i && data?.canWrite && (
            <button
              type="button"
              className="btn btn-icon fav-toggle"
              aria-pressed={i.favorite}
              aria-label="Favorite"
              title={i.favorite ? "Remove from favorites" : "Add to favorites"}
              onClick={() => void toggleFavorite(i)}
            >
              <Icon name="star" />
            </button>
          )}
          <PopOut />
        </>
      }
      footer={footer}
    >
      {i && data && (
        <>
          <section className="card-box item-head">
            <div className="row">
              {kind === "login" ? (
                <SiteIcon host={site ? hostOf(site) : ""} name={i.name} server={ctx.state.server} enabled={ctx.state.iconsShown ?? ctx.state.settings.showIcons} />
              ) : (
                <span className="avatar glyph" aria-hidden="true">
                  <Icon name={GLYPH[kind]} />
                </span>
              )}
              <div className="grow">
                <div className="kind">{KIND_LABEL[kind]}</div>
              </div>
            </div>
            <div className="meta">
              <span>
                <Icon name="folder" size={15} /> {i.folder || "No folder"}
              </span>
              <span>
                <Icon name="vault" size={15} /> {data.vaultName}
                {data.vaultLabel ? ` · ${data.vaultLabel}` : ""}
              </span>
            </div>
            {data.olderVersion && (
              <p className="warn" role="note">
                <Icon name="shield" size={14} /> {data.olderVersion}
              </p>
            )}
            {data.vaultWarning && (
              <p className="warn" role="note">
                <Icon name="shield" size={14} /> {data.vaultWarning}
              </p>
            )}
            {/* L6: a deleted signer's vault keeps its fingerprint line (the label alone shows no fingerprint). */}
            {data.signer && <SignerLine signer={data.signer} />}
            {canFill && (
              <button
                type="button"
                className="btn btn-accent btn-block"
                onClick={() =>
                  callPopup("fill", { id, tabId: tabId! }).then(
                    () => window.close(),
                    (e) => ctx.notify(msg(e)),
                  )
                }
              >
                Fill on this page
              </button>
            )}
          </section>

          {l && (l.username || l.password || l.passkeys.length > 0 || code || i.password_history.length > 0) && (
            <Card title="Login credentials">
              {l.username && (
                <Field label="Username" actions={<CopyBtn ctx={ctx} req={{ id, field: "username" }} label="Username" />}>
                  {l.username}
                </Field>
              )}
              {l.password && (
                <>
                  <Secret ctx={ctx} label="Password" value={l.password} copy={{ id, field: "password" }} large={i.name} />
                  {data.weakPassword && (
                    <p className="warn">
                      <Icon name="shield" size={14} /> This password is easy to guess.{" "}
                      {data.canWrite && (
                        <button type="button" className="link" onClick={() => ctx.go({ tab: "vault", page: "edit", id })}>
                          Change it
                        </button>
                      )}
                    </p>
                  )}
                </>
              )}
              {l.passkeys.map((p) => (
                <Field key={p.credential_id} label="Passkey">
                  {p.user_name || p.rp_id}
                  <span className="sub">Created {formatDate(p.created_at)}</span>
                </Field>
              ))}
              {code && (
                <Field
                  label="Verification code"
                  actions={
                    <>
                      <Ring remaining={code.remaining} period={code.period} />
                      <CopyBtn ctx={ctx} req={{ id, field: "totp" }} label="Verification code" />
                    </>
                  }
                >
                  <span className="totp">
                    <span aria-hidden="true">{first}</span>
                    <span aria-hidden="true">{second}</span>
                    <span className="sr-only">{code.code.split("").join(" ")}</span>
                  </span>
                </Field>
              )}
              {i.password_history.length > 0 && (
                <button type="button" className="kv kv-link" onClick={() => ctx.go({ tab: "vault", page: "history", id })}>
                  <span className="grow">Password history ({i.password_history.length})</span>
                  <Icon name="chevron" size={16} />
                </button>
              )}
            </Card>
          )}

          {i.card && (
            <Card title="Card details">
              {i.card.cardholder_name && <Field label="Cardholder name">{i.card.cardholder_name}</Field>}
              {i.card.number && <Secret ctx={ctx} label="Number" value={i.card.number} />}
              {(i.card.exp_month || i.card.exp_year) && (
                <Field label="Expires">
                  {i.card.exp_month}/{i.card.exp_year}
                </Field>
              )}
              {i.card.code && <Secret ctx={ctx} label="Security code" value={i.card.code} />}
            </Card>
          )}

          {i.identity && (
            <Card title="Personal details">
              {/* The same fields as the web vault; ID, passport and licence numbers stay hidden until revealed, like a password. */}
              {identityRows(i.identity).map((r) =>
                r.secret ? (
                  <Secret key={r.label} ctx={ctx} label={r.label} value={r.value} />
                ) : (
                  <Field key={r.label} label={r.label} actions={<CopyBtn ctx={ctx} req={{ text: r.value }} label={r.label} />}>
                    {r.value}
                  </Field>
                ),
              )}
            </Card>
          )}

          {i.ssh_key && (
            <Card title="SSH key">
              {i.ssh_key.public_key && (
                <Field label="Public key" actions={<CopyBtn ctx={ctx} req={{ text: i.ssh_key.public_key }} label="Public key" />}>
                  <span className="mono clip">{i.ssh_key.public_key}</span>
                </Field>
              )}
              {i.ssh_key.fingerprint && <Field label="Fingerprint">{i.ssh_key.fingerprint}</Field>}
              {i.ssh_key.private_key && <Secret ctx={ctx} label="Private key" value={i.ssh_key.private_key} />}
            </Card>
          )}

          {l?.urls.some((u) => u.url) && (
            <Card title="Autofill options">
              {l.urls
                .map((u, at) => ({ u, at }))
                .filter(({ u }) => u.url)
                .map(({ u, at }, n) => (
                  <Field
                    // biome-ignore lint/suspicious/noArrayIndexKey: a saved item's websites have no id; the page is drawn anew for every visit
                    key={n}
                    label={l.urls.length > 1 ? `Website ${n + 1}` : "Website"}
                    actions={
                      <>
                        {/^https?:\/\//i.test(u.url) && u.match !== "regex" && (
                          <a className="btn btn-icon" href={u.url} target="_blank" rel="noreferrer" aria-label="Open website" title="Open website">
                            <Icon name="external" />
                          </a>
                        )}
                        <CopyBtn ctx={ctx} req={{ text: u.url }} label="Website" />
                      </>
                    }
                  >
                    <span className="clip">{u.url}</span>
                    {data.regexErrors?.[at] && <span className="sub warn-text">Never matches a page: {data.regexErrors[at]}</span>}
                  </Field>
                ))}
            </Card>
          )}

          {i.fields.length > 0 && (
            <Card title="Custom fields">
              {i.fields.map((f, n) =>
                f.type === "hidden" ? (
                  // biome-ignore lint/suspicious/noArrayIndexKey: custom fields have no id; the page is drawn anew for every visit
                  <Secret key={n} ctx={ctx} label={f.name || "Hidden field"} value={f.value} />
                ) : (
                  // biome-ignore lint/suspicious/noArrayIndexKey: custom fields have no id; the page is drawn anew for every visit
                  <Field key={n} label={f.name || "Field"} actions={f.type === "text" && f.value ? <CopyBtn ctx={ctx} req={{ text: f.value }} label={f.name || "Field"} /> : undefined}>
                    {f.type === "boolean" ? (f.value === "true" ? "Yes" : "No") : f.value}
                  </Field>
                ),
              )}
            </Card>
          )}

          {/* Files attached in the web vault (servers with attachments): download them here. */}
          <Files itemId={id} item={i} ctx={ctx} />

          {i.notes && (
            <Card title="Notes" actions={<CopyBtn ctx={ctx} req={{ text: i.notes }} label="Notes" />}>
              <p className="notes">{i.notes}</p>
            </Card>
          )}

          <Card title="Item history">
            <p className="history">
              {i.updated_at > 0 && <span>Last edited {formatDate(i.updated_at)}</span>}
              {i.created_at > 0 && <span>Created {formatDate(i.created_at)}</span>}
              {i.password_history[0] && <span>Password changed {formatDate(i.password_history[0].changed_at)}</span>}
            </p>
          </Card>

          {confirmDelete && (
            <ConfirmDialog
              title="Move to trash?"
              subtitle={i.name}
              icon="trash"
              action="Move to trash"
              busyAction="Moving to trash…"
              onClose={() => setConfirmDelete(false)}
              onConfirm={async () => {
                await callPopup("trashItem", { id });
                ctx.notify("Moved to trash. You can restore it from the web vault.");
                back();
              }}
            >
              <p className="card-text">The item leaves your vault on every device. You can restore it from the trash in the web vault.</p>
            </ConfirmDialog>
          )}
        </>
      )}
    </Page>
  );
}

/** A login's earlier passwords, newest first: reveal, large type and copy each. */
export function HistoryPage({ id, ctx }: { id: string; ctx: Ctx }) {
  const [data] = useItem(id, ctx);
  const history = data?.item.password_history ?? [];
  return (
    <Page title="Password history" onBack={() => ctx.go({ tab: "vault", page: "item", id })} actions={<PopOut />}>
      {data &&
        (history.length ? (
          <section className="group">
            <h2 className="group-title">
              <span>{data.item.name}</span>
              <span className="count">{history.length}</span>
            </h2>
            <div className="card-box">
              {history.map((h, n) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: history entries have no id; the page is drawn anew for every visit
                <Secret key={n} ctx={ctx} label={`Changed ${formatDate(h.changed_at)}`} value={h.password} large={data.item.name} />
              ))}
            </div>
            <p className="small muted">Copies clear from the clipboard like any other password.</p>
          </section>
        ) : (
          <div className="empty">
            <p className="empty-title">No earlier passwords</p>
          </div>
        ))}
    </Page>
  );
}
