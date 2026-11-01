/** Mirrors `passauth_core::item` (snake_case JSON). */

export type UrlMatch = "domain" | "host" | "starts_with" | "exact" | "never";
export type FieldType = "text" | "hidden" | "boolean";

export interface LoginUrl {
  url: string;
  match: UrlMatch;
}

export interface Passkey {
  credential_id: string;
  rp_id: string;
  rp_name: string;
  user_handle: string;
  user_name: string;
  user_display_name: string;
  algorithm: number;
  private_key: string;
  counter: number;
  discoverable: boolean;
  created_at: number;
}

export interface Login {
  username: string;
  password: string;
  urls: LoginUrl[];
  totp: string | null;
  passkeys: Passkey[];
}

export interface Card {
  cardholder_name: string;
  brand: string;
  number: string;
  exp_month: string;
  exp_year: string;
  code: string;
}

export interface Identity {
  title: string;
  first_name: string;
  middle_name: string;
  last_name: string;
  company: string;
  email: string;
  phone: string;
  address1: string;
  address2: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
  username: string;
  ssn: string;
  passport_number: string;
  license_number: string;
}

export interface SshKey {
  private_key: string;
  public_key: string;
  fingerprint: string;
}

export interface Field {
  name: string;
  value: string;
  type: FieldType;
}

export interface Item {
  name: string;
  notes: string;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  login: Login | null;
  card: Card | null;
  identity: Identity | null;
  ssh_key: SshKey | null;
  fields: Field[];
  password_history: { password: string; changed_at: number }[];
  created_at: number;
  updated_at: number;
}

export type ItemKind = "login" | "note" | "card" | "identity" | "ssh_key";

export function kindOf(i: Item): ItemKind {
  if (i.login) return "login";
  if (i.card) return "card";
  if (i.identity) return "identity";
  if (i.ssh_key) return "ssh_key";
  return "note";
}

export const KIND_LABEL: Record<ItemKind, string> = {
  login: "Login",
  note: "Secure note",
  card: "Card",
  identity: "Identity",
  ssh_key: "SSH key",
};

export function emptyItem(kind: ItemKind): Item {
  const now = Math.floor(Date.now() / 1000);
  return {
    name: "",
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: kind === "login" ? { username: "", password: "", urls: [{ url: "", match: "domain" }], totp: null, passkeys: [] } : null,
    card: kind === "card" ? { cardholder_name: "", brand: "", number: "", exp_month: "", exp_year: "", code: "" } : null,
    identity:
      kind === "identity"
        ? { title: "", first_name: "", middle_name: "", last_name: "", company: "", email: "", phone: "", address1: "", address2: "", city: "", state: "", postal_code: "", country: "", username: "", ssn: "", passport_number: "", license_number: "" }
        : null,
    ssh_key: kind === "ssh_key" ? { private_key: "", public_key: "", fingerprint: "" } : null,
    fields: [],
    password_history: [],
    created_at: now,
    updated_at: now,
  };
}

export interface EncryptedItem {
  id: string;
  vault_id: string;
  key: string;
  data: string;
}

export interface VaultEntry {
  id: string;
  item: Item;
  vaultId: string;
  revision: number;
  deletedAt: number | null;
  enc: EncryptedItem;
}

export type Role = "owner" | "admin" | "write" | "read";
