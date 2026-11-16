/**
 * Where the API lives. The web vault is served by its own server (base ""), so it uses relative URLs;
 * the desktop app points this at any server and routes requests through its native HTTP client.
 */
type Fetch = typeof globalThis.fetch;

/** An answer as a native client hands it over: status, the headers the app reads (lower-case names) and the text. */
export interface NativeAnswer {
  status: number;
  /** `content-type`, `retry-after` and `x-request-id`, when the answer has them. */
  headers: Record<string, string>;
  body: string;
}

/**
 * Attachment files through a native client (the desktop app, whose `fetch` carries text only): the encrypted bytes move
 * piece by piece. `files.ts` keeps the rules (renewing the session, retries); this is one request per call. The browser
 * and the extension don't set it.
 */
export interface NativeTransfers {
  /** Start `PUT /api{path}` with a body of exactly `size` bytes; `sent` hears how many went out. Resolves with its id. */
  uploadStart(path: string, headers: Record<string, string>, size: number, sent: (bytes: number) => void): Promise<number>;
  /** Hand over the next piece. False once the request has ended (the server answered early): `uploadFinish` tells how. */
  uploadChunk(id: number, piece: Uint8Array): Promise<boolean>;
  /** Every piece is handed over (or the request ended): the server's answer. */
  uploadFinish(id: number): Promise<NativeAnswer>;
  /** `GET /api{path}`. A 2xx answer's body waits under `id` for `downloadRead`; other answers come whole (`id` null). */
  downloadStart(path: string, headers: Record<string, string>): Promise<NativeAnswer & { id: number | null }>;
  /** The next bytes of a download's body; empty at its end. */
  downloadRead(id: number): Promise<Uint8Array>;
  /** Stop a transfer and drop what it holds (nothing happens for one that has ended). */
  cancel(id: number): Promise<void>;
}

export const server = {
  base: "",
  fetch: globalThis.fetch.bind(globalThis) as Fetch,
  /** Desktop: attachment files go through the native client. Null in the browser and the extension. */
  transfers: null as NativeTransfers | null,
  host: (): string => (server.base ? new URL(server.base).host : location.host),
  origin: (): string => server.base || location.origin,
  /** `path` is relative to `/api`, e.g. `/auth/refresh`. */
  apiUrl: (path: string): string => `${server.base}/api${path}`,
  wsUrl: (path: string): string => `${server.origin().replace(/^http/, "ws")}/api${path}`,
};

export function configureServer(config: { base: string; fetch: Fetch; transfers?: NativeTransfers }) {
  server.base = config.base.replace(/\/+$/, "");
  server.fetch = config.fetch;
  server.transfers = config.transfers ?? null;
}
