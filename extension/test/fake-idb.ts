/**
 * A small in-memory IndexedDB with the surface background/storage.ts uses for the offline copy (open with an
 * upgrade, one object store, get / put / delete in a transaction, close). Values are structured-cloned, and every
 * step completes on a later tick, as in the browser. Installed by test/chrome.ts `installChrome()`, fresh each time.
 */

type Handler = (() => void) | null;

class FakeRequest<T> {
  result!: T;
  error: DOMException | null = null;
  onsuccess: Handler = null;
  onerror: Handler = null;
}

class FakeStore {
  constructor(private readonly data: Map<IDBValidKey, unknown>) {}
  private request<T>(run: () => T): FakeRequest<T> {
    const r = new FakeRequest<T>();
    r.result = run();
    return r;
  }
  get(key: IDBValidKey) {
    return this.request(() => (this.data.has(key) ? structuredClone(this.data.get(key)) : undefined));
  }
  put(value: unknown, key: IDBValidKey) {
    return this.request(() => {
      this.data.set(key, structuredClone(value));
      return key;
    });
  }
  delete(key: IDBValidKey) {
    return this.request(() => {
      this.data.delete(key);
      return undefined;
    });
  }
}

class FakeTransaction {
  oncomplete: Handler = null;
  onerror: Handler = null;
  onabort: Handler = null;
  error: DOMException | null = null;
  constructor(private readonly store: FakeStore) {
    setTimeout(() => this.oncomplete?.(), 0);
  }
  objectStore() {
    return this.store;
  }
}

class FakeDatabase {
  readonly stores = new Map<string, Map<IDBValidKey, unknown>>();
  version = 0;
  createObjectStore(name: string) {
    this.stores.set(name, new Map());
  }
  transaction(name: string) {
    const data = this.stores.get(name);
    if (!data) throw new DOMException(`No object store ${name}`, "NotFoundError");
    return new FakeTransaction(new FakeStore(data));
  }
  close() {}
}

class FakeOpenRequest extends FakeRequest<FakeDatabase> {
  onupgradeneeded: Handler = null;
}

export function fakeIndexedDb() {
  const databases = new Map<string, FakeDatabase>();
  return {
    databases,
    open(name: string, version = 1) {
      const r = new FakeOpenRequest();
      setTimeout(() => {
        let db = databases.get(name);
        if (!db) {
          db = new FakeDatabase();
          databases.set(name, db);
        }
        r.result = db;
        if (db.version < version) {
          db.version = version;
          r.onupgradeneeded?.();
        }
        r.onsuccess?.();
      }, 0);
      return r;
    },
  };
}
