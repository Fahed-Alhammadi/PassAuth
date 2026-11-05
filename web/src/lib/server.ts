/**
 * Where the API lives. The web vault is served by its own server (base ""), so it uses relative URLs;
 * the desktop app points this at any server and routes requests through its native HTTP client.
 */
type Fetch = typeof globalThis.fetch;

export const server = {
  base: "",
  fetch: globalThis.fetch.bind(globalThis) as Fetch,
  host: (): string => (server.base ? new URL(server.base).host : location.host),
  origin: (): string => server.base || location.origin,
  /** `path` is relative to `/api`, e.g. `/auth/refresh`. */
  apiUrl: (path: string): string => `${server.base}/api${path}`,
  wsUrl: (path: string): string => `${server.origin().replace(/^http/, "ws")}/api${path}`,
};

export function configureServer(config: { base: string; fetch: Fetch }) {
  server.base = config.base.replace(/\/+$/, "");
  server.fetch = config.fetch;
}
