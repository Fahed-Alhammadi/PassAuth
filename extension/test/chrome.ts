/**
 * A small hand-written fake of the `chrome` extension APIs the extension uses,
 * for unit tests in Node. Storage is asynchronous (every call yields first), so
 * read-modify-write races show up as they would in the browser. Only what the
 * code under test touches is implemented; anything else is a harmless stub.
 */

import { fakeIndexedDb } from "./fake-idb";
import { FakeWebSocket } from "./fake-socket";

type Fn = (...args: any[]) => any;

export class FakeEvent<F extends Fn = Fn> {
  readonly listeners: F[] = [];
  addListener(fn: F) {
    this.listeners.push(fn);
  }
  removeListener(fn: F) {
    const i = this.listeners.indexOf(fn);
    if (i >= 0) this.listeners.splice(i, 1);
  }
  hasListener(fn: F) {
    return this.listeners.includes(fn);
  }
  dispatch(...args: Parameters<F>): unknown[] {
    return [...this.listeners].map((l) => l(...args));
  }
}

/** Let other pending promise callbacks run, like a real storage round trip. */
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

type Changes = Record<string, { oldValue?: unknown; newValue?: unknown }>;

function storageArea(name: "local" | "session", onAnyChange: FakeEvent) {
  const data = new Map<string, unknown>();
  const onChanged = new FakeEvent();
  const emit = (changes: Changes) => {
    if (!Object.keys(changes).length) return;
    onChanged.dispatch(changes);
    onAnyChange.dispatch(changes, name);
  };
  return {
    data,
    onChanged,
    /** What setAccessLevel last set (Chrome's default: content scripts may read local storage, not session storage). */
    accessLevel: name === "session" ? "TRUSTED_CONTEXTS" : "TRUSTED_AND_UNTRUSTED_CONTEXTS",
    async setAccessLevel(this: { accessLevel: string }, options: { accessLevel: string }) {
      await tick();
      this.accessLevel = options.accessLevel;
    },
    async get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, any>> {
      await tick();
      const out: Record<string, unknown> = {};
      if (keys == null) {
        for (const [k, v] of data) out[k] = structuredClone(v);
        return out;
      }
      const list = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
      for (const k of list) {
        if (data.has(k)) out[k] = structuredClone(data.get(k));
        else if (typeof keys === "object" && !Array.isArray(keys)) out[k] = keys[k];
      }
      return out;
    },
    async set(items: Record<string, unknown>) {
      await tick();
      const changes: Changes = {};
      for (const [k, v] of Object.entries(items)) {
        if (v === undefined) continue;
        changes[k] = { oldValue: data.get(k), newValue: structuredClone(v) };
        data.set(k, structuredClone(v));
      }
      emit(changes);
    },
    async remove(keys: string | string[]) {
      await tick();
      const changes: Changes = {};
      for (const k of typeof keys === "string" ? [keys] : keys) {
        if (!data.has(k)) continue;
        changes[k] = { oldValue: data.get(k) };
        data.delete(k);
      }
      emit(changes);
    },
    async clear() {
      await tick();
      const changes: Changes = {};
      for (const [k, v] of data) changes[k] = { oldValue: v };
      data.clear();
      emit(changes);
    },
  };
}

export interface SentToTab {
  tabId: number;
  message: any;
  options?: { frameId?: number; documentId?: string };
}

export interface FakeTab {
  id: number;
  url: string;
  windowId: number;
  active?: boolean;
}

export const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";

export function createChrome() {
  const storageChanged = new FakeEvent();
  const local = storageArea("local", storageChanged);
  const session = storageArea("session", storageChanged);
  const alarms = new Map<string, { name: string; scheduledTime: number; delayInMinutes?: number }>();
  const tabs = new Map<number, FakeTab>();
  const sentToTabs: SentToTab[] = [];
  /** Answers chrome.tabs.sendMessage; default: no receiver (rejects like Chrome). */
  let tabResponder: (s: SentToTab) => unknown = () => {
    throw new Error("Could not establish connection. Receiving end does not exist.");
  };
  const runtimeMessages: unknown[] = [];
  let windowSeq = 100;
  /** chrome.contextMenus entries as created, by id (in creation order). */
  const menus = new Map<string, Record<string, any>>();
  /** chrome.commands.getAll() answers this. */
  const commands: { name: string; description?: string; shortcut?: string }[] = [];
  /** The toolbar icon's title and what was set as its icon. */
  const action = { title: "PassAuth", icon: null as unknown, popupOpened: 0, badges: new Map<number, { text?: string; color?: string }>() };
  /** URLs of tabs PassAuth opened (chrome.tabs.create). */
  const createdTabs: string[] = [];

  const chrome = {
    runtime: {
      id: EXTENSION_ID,
      lastError: undefined as undefined | { message: string },
      getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path.replace(/^\//, "")}`,
      getManifest: () => ({ manifest_version: 3, name: "PassAuth", version: "9.8.7" }),
      getPlatformInfo: async () => ({ os: "mac", arch: "arm64" }),
      getContexts: async () => [] as unknown[],
      ContextType: { OFFSCREEN_DOCUMENT: "OFFSCREEN_DOCUMENT" },
      onMessage: new FakeEvent<(msg: any, sender: any, respond: (r: unknown) => void) => unknown>(),
      onConnect: new FakeEvent(),
      onStartup: new FakeEvent(),
      onInstalled: new FakeEvent(),
      async sendMessage(message: unknown) {
        runtimeMessages.push(message);
        return undefined;
      },
      connect: () => ({ postMessage() {}, onDisconnect: new FakeEvent(), onMessage: new FakeEvent(), disconnect() {} }),
    },
    storage: { local, session, onChanged: storageChanged },
    alarms: {
      async create(name: string, info: { delayInMinutes?: number; when?: number }) {
        alarms.set(name, { name, delayInMinutes: info.delayInMinutes, scheduledTime: info.when ?? Date.now() + (info.delayInMinutes ?? 0) * 60_000 });
      },
      async clear(name: string) {
        return alarms.delete(name);
      },
      async get(name: string) {
        return alarms.get(name);
      },
      async getAll() {
        return [...alarms.values()];
      },
      onAlarm: new FakeEvent(),
    },
    idle: { setDetectionInterval() {}, onStateChanged: new FakeEvent() },
    tabs: {
      async query(q: { active?: boolean } = {}) {
        return [...tabs.values()].filter((t) => q.active === undefined || !!t.active === q.active);
      },
      async get(id: number) {
        const t = tabs.get(id);
        if (!t) throw new Error(`No tab with id: ${id}.`);
        return t;
      },
      async sendMessage(tabId: number, message: unknown, options?: SentToTab["options"]) {
        const s: SentToTab = { tabId, message: structuredClone(message), options };
        sentToTabs.push(s);
        return tabResponder(s);
      },
      async create(props: { url: string }) {
        createdTabs.push(props.url);
        return { id: 999, url: props.url, windowId: 1 };
      },
      async getZoom() {
        return 1;
      },
      onActivated: new FakeEvent(),
      onUpdated: new FakeEvent(),
      onRemoved: new FakeEvent(),
    },
    windows: {
      async create(props: Record<string, unknown>) {
        return { id: ++windowSeq, type: "popup", state: "normal", ...props };
      },
      async remove() {},
      async get(id: number) {
        return { id, left: 0, top: 0, width: 1280, height: 800, state: "normal", type: "normal" };
      },
      async getCurrent() {
        return { id: 1, left: 0, top: 0, width: 1280, height: 800, state: "normal", type: "normal" };
      },
      async getLastFocused() {
        return { id: 1, left: 0, top: 0, width: 1280, height: 800, state: "normal", type: "normal" };
      },
      async update() {},
      onRemoved: new FakeEvent(),
      onFocusChanged: new FakeEvent(),
    },
    action: {
      async setBadgeText(d: { tabId?: number; text: string }) {
        if (d.tabId !== undefined) action.badges.set(d.tabId, { ...action.badges.get(d.tabId), text: d.text });
      },
      async setBadgeBackgroundColor(d: { tabId?: number; color: string }) {
        if (d.tabId !== undefined) action.badges.set(d.tabId, { ...action.badges.get(d.tabId), color: d.color });
      },
      async setBadgeTextColor() {},
      async setTitle(d: { title: string }) {
        action.title = d.title;
      },
      async setIcon(d: unknown) {
        action.icon = d;
      },
      async openPopup() {
        action.popupOpened++;
        throw new Error("No active browser window.");
      },
    },
    contextMenus: {
      ACTION_MENU_TOP_LEVEL_LIMIT: 6,
      create(props: Record<string, any>, done?: () => void) {
        if (menus.has(props.id)) (chrome.runtime as { lastError?: { message: string } }).lastError = { message: `Cannot create item with duplicate id ${props.id}` };
        else menus.set(props.id, structuredClone(props));
        done?.();
        (chrome.runtime as { lastError?: unknown }).lastError = undefined;
        return props.id;
      },
      async removeAll() {
        await tick();
        menus.clear();
      },
      async remove(id: string) {
        menus.delete(id);
      },
      async update(id: string, props: Record<string, unknown>) {
        const m = menus.get(id);
        if (m) Object.assign(m, props);
      },
      onClicked: new FakeEvent(),
    },
    commands: {
      onCommand: new FakeEvent(),
      async getAll() {
        return structuredClone(commands);
      },
    },
    offscreen: { Reason: { CLIPBOARD: "CLIPBOARD" }, async createDocument() {} },
    permissions: {
      async contains() {
        return false;
      },
      async request() {
        return false;
      },
    },
  };

  return {
    chrome,
    local,
    session,
    alarms,
    tabs,
    sentToTabs,
    runtimeMessages,
    menus,
    commands,
    action,
    createdTabs,
    setTabResponder(fn: (s: SentToTab) => unknown) {
      tabResponder = fn;
    },
    /** Deliver a runtime message the way Chrome does and resolve with the listener's answer (undefined if none answers). */
    deliver(message: unknown, sender: Record<string, unknown>): Promise<any> {
      return new Promise((resolve) => {
        let answered = false;
        const respond = (r: unknown) => {
          if (answered) return;
          answered = true;
          resolve(r);
        };
        const results = chrome.runtime.onMessage.dispatch(structuredClone(message), sender, respond);
        if (!results.some((r) => r === true) && !answered) resolve(undefined);
      });
    },
  };
}

export type FakeChrome = ReturnType<typeof createChrome>;

let current: FakeChrome | null = null;

/** Install a fresh fake as the global `chrome` (an empty IndexedDB for the offline copy, a WebSocket that stays off the network) and return it. */
export function installChrome(): FakeChrome {
  const fake = createChrome();
  (globalThis as { chrome?: unknown }).chrome = fake.chrome;
  (globalThis as { indexedDB?: unknown }).indexedDB = fakeIndexedDb();
  FakeWebSocket.all = [];
  (globalThis as { WebSocket?: unknown }).WebSocket = FakeWebSocket;
  current = fake;
  return fake;
}

/** The fake installed last (by test/setup.ts unless the test installed its own): modules that registered listeners at import hold on to it. */
export function installedChrome(): FakeChrome {
  if (!current) throw new Error("no fake chrome installed");
  return current;
}

/** Empty its storage, alarms and recordings, keeping the listeners modules registered on it. */
export function resetChrome(fake: FakeChrome) {
  fake.local.data.clear();
  fake.session.data.clear();
  fake.alarms.clear();
  fake.tabs.clear();
  fake.sentToTabs.length = 0;
  fake.runtimeMessages.length = 0;
  fake.menus.clear();
  fake.createdTabs.length = 0;
  fake.action.popupOpened = 0;
  fake.action.badges.clear();
  fake.setTabResponder(() => {
    throw new Error("Could not establish connection. Receiving end does not exist.");
  });
}
