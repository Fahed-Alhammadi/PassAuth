/**
 * Short-lived page-related state in chrome.storage.session (extension-private,
 * memory-only, survives a service-worker restart), one storage key per record
 * so that concurrent messages can't overwrite each other's records:
 *   save:<tabId>   a typed login waiting for the user's answer in the save prompt
 *   user:<tabId>   the user name typed on the first step of an identifier-first login
 *   menu:<nonce>   an inline autofill menu frame
 */
import { scratch } from "./storage";

export interface Expiring {
  expires: number;
}

export interface Store<T extends Expiring> {
  get(id: string | number): Promise<T | undefined>;
  put(id: string | number, value: T): Promise<void>;
  remove(id: string | number): Promise<void>;
  /** Every live record, by id (expired ones are removed on the way). */
  all(): Promise<[string, T][]>;
  /** Remove every record (lock, sign-out). */
  clear(): Promise<string[]>;
}

export function store<T extends Expiring>(prefix: string): Store<T> {
  const key = (id: string | number) => `${prefix}${id}`;
  const raw = async () => Object.entries(await chrome.storage.session.get(null)).filter(([k]) => k.startsWith(prefix)) as [string, T][];
  return {
    async get(id) {
      const v = await scratch.get<T>(key(id));
      return v && typeof v.expires === "number" && v.expires > Date.now() ? v : undefined;
    },
    put: (id, value) => scratch.set(key(id), value),
    remove: (id) => scratch.remove(key(id)),
    async all() {
      const live: [string, T][] = [];
      const dead: string[] = [];
      for (const [k, v] of await raw()) v && v.expires > Date.now() ? live.push([k.slice(prefix.length), v]) : dead.push(k);
      if (dead.length) await chrome.storage.session.remove(dead);
      return live;
    },
    async clear() {
      const keys = (await raw()).map(([k]) => k);
      if (keys.length) await chrome.storage.session.remove(keys);
      return keys.map((k) => k.slice(prefix.length));
    },
  };
}
