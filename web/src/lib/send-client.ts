/**
 * Send, the owner's side: encrypt, list, change and delete Sends (`sends.ts` has the rules, unit-tested). The send key
 * is made here, put only in the link and kept wrapped by the account key, so the account's handle is needed for
 * everything but deleting; it is looked up at each call (a lock frees it).
 */
import * as core from "../wasm/passauth_core";
import { api, hasFeature, knownPublicConfig, loadPublicConfig } from "./api";
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

/** A v2 Send's content key, from its `owner_content_key` (null for v1 Sends). */
const contentKeyOf = (s: OwnedSend): string | null => (s.ownerContentKey ? account().unwrapSendContentKey(s.ownerContentKey) : null);

/** The link to share. */
export const linkOf = (s: OwnedSend): string => sendLink(server.origin(), s.id, sendKeyOf(s));

/** One of the Send's fields, either version (`sendOpen`: v2 needs the content key). */
const openField = (s: OwnedSend, field: "name" | "data", ciphertext: string): string => core.sendOpen(sendKeyOf(s), contentKeyOf(s), field, ciphertext);

/**
 * The Send's name, or null when it can't be decrypted (made by an account key this account no longer has, or a v2
 * Send without a content key this account can open).
 */
export function nameOf(s: OwnedSend): string | null {
  try {
    return openField(s, "name", s.name);
  } catch {
    return null;
  }
}

/** The Send's text (`data`, from `GET /sends/{id}`). */
export function textOf(s: OwnedSend): string {
  if (s.data === null) throw new Error(UNEXPECTED);
  return openField(s, "data", s.data);
}

/** Whether the server takes Send v2 (`owner_content_key`): an older one would drop it, so v1 is written then. */
async function sendV2On(): Promise<boolean> {
  return hasFeature(knownPublicConfig() ?? (await loadPublicConfig()), "send_v2");
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

/** A new password's salt and verifier (Argon2id, about a second), v1: the server keeps only the verifier's hash. */
function passwordFields(password: string) {
  const salt = core.sendPasswordSalt();
  return { salt, verifier: core.sendPasswordVerifier(password, salt) };
}

/**
 * Send v2: a new password's salt, verifier and content key, from one Argon2id run (`sendPasswordKeys`). The content
 * key needs the link key and the password, so the server (and anyone with only the link) can't open the text.
 */
function passwordKeys(password: string, key: string): { salt: string; verifier: string; contentKey: string } {
  const salt = core.sendPasswordSalt();
  const pk = core.sendPasswordKeys(password, salt, key);
  try {
    return { salt, verifier: pk.verifier, contentKey: pk.contentKey };
  } finally {
    pk.free();
  }
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

/**
 * Encrypt and save a new Send; resolves with it and its link (the only place its key is shown). With a password on a
 * server with `send_v2`, the text is encrypted with the password too (v2); otherwise v1 as before.
 */
export async function createSend(d: NewSend): Promise<{ send: OwnedSend; link: string }> {
  const key = core.sendNewKey();
  const body: Record<string, unknown> = {
    kind: "text",
    owner_key: account().wrapSendKey(key),
    max_views: d.maxViews,
    expires_at: d.expiresAt,
    delete_at: d.deleteAt,
    hide_email: d.hideEmail,
    disabled: false,
  };
  if (d.password && (await sendV2On())) {
    const p = passwordKeys(d.password, key);
    body.name = core.sendEncryptV2(p.contentKey, "name", d.name);
    body.data = core.sendEncryptV2(p.contentKey, "data", d.text);
    body.owner_content_key = account().wrapSendContentKey(p.contentKey);
    body.access_salt = p.salt;
    body.access_verifier = p.verifier;
  } else {
    body.name = core.sendEncrypt(key, "name", d.name);
    body.data = core.sendEncrypt(key, "data", d.text);
    if (d.password) {
      const p = passwordFields(d.password);
      body.access_salt = p.salt;
      body.access_verifier = p.verifier;
    }
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

/**
 * Save changes to a Send: only what changed is sent. Name and text keep the Send's format: v1 with the send key (the
 * link has it), v2 with its content key. Setting or changing the password (server with `send_v2`) makes it v2 with a
 * new salt and content key, and removing it makes it v1: both encrypt name and text again, so both are sent with it.
 */
export async function updateSend(s: OwnedSend, edit: SendEdit): Promise<OwnedSend> {
  const changes: SendChanges = {
    maxViews: edit.maxViews,
    expiresAt: edit.expiresAt,
    deleteAt: edit.deleteAt,
    disabled: edit.disabled,
    hideEmail: edit.hideEmail,
  };
  const v2 = s.ownerContentKey !== null;
  const toV2 = typeof edit.password === "string" && edit.password !== "" && (await sendV2On());
  const toV1 = (edit.password === null && v2) || (typeof edit.password === "string" && edit.password !== "" && !toV2 && v2);
  if (toV2 || toV1) {
    // Re-keyed: both fields encrypted again, from what the owner changed or what the Send holds now.
    const name = edit.name ?? openField(s, "name", s.name);
    const text = edit.text ?? textOf(s.data === null ? await getSend(s.id) : s);
    const key = sendKeyOf(s);
    if (toV2) {
      const p = passwordKeys(edit.password as string, key);
      changes.name = core.sendEncryptV2(p.contentKey, "name", name);
      changes.data = core.sendEncryptV2(p.contentKey, "data", text);
      changes.password = { salt: p.salt, verifier: p.verifier };
      changes.ownerContentKey = account().wrapSendContentKey(p.contentKey);
    } else {
      changes.name = core.sendEncrypt(key, "name", name);
      changes.data = core.sendEncrypt(key, "data", text);
      changes.password = edit.password ? passwordFields(edit.password) : null;
      changes.ownerContentKey = null;
    }
  } else {
    if (edit.name !== undefined || edit.text !== undefined) {
      const ck = v2 ? contentKeyOf(s) : null;
      const seal = (field: "name" | "data", plaintext: string) => (ck ? core.sendEncryptV2(ck, field, plaintext) : core.sendEncrypt(sendKeyOf(s), field, plaintext));
      if (edit.name !== undefined) changes.name = seal("name", edit.name);
      if (edit.text !== undefined) changes.data = seal("data", edit.text);
    }
    if (edit.password === null) changes.password = null;
    else if (edit.password) changes.password = passwordFields(edit.password);
  }
  const send = readSend(await api(`/sends/${encodeURIComponent(s.id)}`, { method: "PUT", body: changesBody(changes) }));
  if (!send) throw new Error(UNEXPECTED);
  return send;
}

export async function deleteSend(id: string): Promise<void> {
  await api(`/sends/${encodeURIComponent(id)}`, { method: "DELETE" });
}
