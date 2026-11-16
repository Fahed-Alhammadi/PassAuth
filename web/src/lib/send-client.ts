/**
 * Send, the owner's side: encrypt, list, change and delete Sends (`sends.ts` has the rules, unit-tested). The send key
 * is made here, put only in the link and kept wrapped by the account key, so the account's handle is needed for
 * everything but deleting; it is looked up at each call (a lock frees it).
 */
import * as core from "../wasm/passauth_core";
import { api } from "./api";
import { server } from "./server";
import { changesBody, readSend, readSends, sendLink, type OwnedSend, type SendChanges } from "./sends";
import { getAccount } from "./vault";

const LOCKED = "The vault is locked. Unlock it and try again.";
const UNEXPECTED = "The server sent an unexpected response. Try again.";

function account() {
  const a = getAccount();
  if (!a) throw new Error(LOCKED);
  return a;
}

/** The Send's key (for its link and its text), from its `owner_key`. */
export const sendKeyOf = (s: OwnedSend): string => account().unwrapSendKey(s.ownerKey);

/** The link to share. */
export const linkOf = (s: OwnedSend): string => sendLink(server.origin(), s.id, sendKeyOf(s));

/** The Send's name, or null when it can't be decrypted (made by an account key this account no longer has). */
export function nameOf(s: OwnedSend): string | null {
  try {
    return core.sendDecrypt(sendKeyOf(s), "name", s.name);
  } catch {
    return null;
  }
}

/** The Send's text (`data`, from `GET /sends/{id}`). */
export function textOf(s: OwnedSend): string {
  if (s.data === null) throw new Error(UNEXPECTED);
  return core.sendDecrypt(sendKeyOf(s), "data", s.data);
}

export async function listSends(): Promise<OwnedSend[]> {
  return readSends(await api("/sends"));
}

/** One Send with its text. */
export async function getSend(id: string): Promise<OwnedSend> {
  const s = readSend(await api(`/sends/${encodeURIComponent(id)}`));
  if (!s) throw new Error(UNEXPECTED);
  return s;
}

/** A new password's salt and verifier (Argon2id, about a second): the server keeps only the verifier's hash. */
function passwordFields(password: string) {
  const salt = core.sendPasswordSalt();
  return { salt, verifier: core.sendPasswordVerifier(password, salt) };
}

export interface NewSend {
  name: string;
  text: string;
  password: string | null;
  maxViews: number | null;
  expiresAt: number | null;
  deleteAt: number;
  hideEmail: boolean;
}

/** Encrypt and save a new Send; resolves with it and its link (the only place its key is shown). */
export async function createSend(d: NewSend): Promise<{ send: OwnedSend; link: string }> {
  const key = core.sendNewKey();
  const body: Record<string, unknown> = {
    kind: "text",
    name: core.sendEncrypt(key, "name", d.name),
    data: core.sendEncrypt(key, "data", d.text),
    owner_key: account().wrapSendKey(key),
    max_views: d.maxViews,
    expires_at: d.expiresAt,
    delete_at: d.deleteAt,
    hide_email: d.hideEmail,
    disabled: false,
  };
  if (d.password) {
    const p = passwordFields(d.password);
    body.access_salt = p.salt;
    body.access_verifier = p.verifier;
  }
  const send = readSend(await api("/sends", { body }));
  if (!send) throw new Error(UNEXPECTED);
  return { send, link: sendLink(server.origin(), send.id, key) };
}

/** What the owner changed: plaintext name and text, a new password (null removes it), and settings. */
export interface SendEdit {
  name?: string;
  text?: string;
  password?: string | null;
  maxViews?: number | null;
  expiresAt?: number | null;
  deleteAt?: number;
  disabled?: boolean;
  hideEmail?: boolean;
}

/** Save changes to a Send: only what changed is sent; name and text are encrypted again with the same key (the link has it). */
export async function updateSend(s: OwnedSend, edit: SendEdit): Promise<OwnedSend> {
  const changes: SendChanges = {
    maxViews: edit.maxViews,
    expiresAt: edit.expiresAt,
    deleteAt: edit.deleteAt,
    disabled: edit.disabled,
    hideEmail: edit.hideEmail,
  };
  if (edit.name !== undefined || edit.text !== undefined) {
    const key = sendKeyOf(s);
    if (edit.name !== undefined) changes.name = core.sendEncrypt(key, "name", edit.name);
    if (edit.text !== undefined) changes.data = core.sendEncrypt(key, "data", edit.text);
  }
  if (edit.password === null) changes.password = null;
  else if (edit.password) changes.password = passwordFields(edit.password);
  const send = readSend(await api(`/sends/${encodeURIComponent(s.id)}`, { method: "PUT", body: changesBody(changes) }));
  if (!send) throw new Error(UNEXPECTED);
  return send;
}

export async function deleteSend(id: string): Promise<void> {
  await api(`/sends/${encodeURIComponent(id)}`, { method: "DELETE" });
}
