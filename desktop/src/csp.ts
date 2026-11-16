/**
 * The WebView's network policy, narrowed to the connected server. tauri.conf.json's Content-Security-Policy is fixed at
 * build time, before anyone picks a server, so it has to allow any `wss:` host (live sync) and any `https:` image (site
 * icons). A second policy in a `<meta>` tag is enforced together with it (a request must pass both), so once the server
 * is known the WebView reaches only that server's WebSocket and icons, besides its own files, the IPC and the breach
 * check. A policy can't be loosened once added: a page pinned to one server is reloaded before it boots another.
 */

/** The attribute on the pinned policy's `<meta>`: the server's origin. */
const PINNED = "data-passauth-server";

/**
 * The policy for the server at `base` (an origin), or null when a policy can't name its host: CSP has no syntax for
 * IPv6 literals, so such a server keeps the build-time policy.
 */
export function serverPolicy(base: string): string | null {
  const url = new URL(base);
  if (url.hostname.startsWith("[")) return null;
  const socket = `${url.protocol === "https:" ? "wss:" : "ws:"}//${url.host}`;
  return [
    `connect-src 'self' ipc: http://ipc.localhost https://api.pwnedpasswords.com ${socket}`,
    `img-src 'self' data: blob: ${url.origin}`,
  ].join("; ");
}

/** Narrow this page's policy to the server at `base`. False when the page is pinned to another server already. */
export function pinServerPolicy(base: string): boolean {
  const origin = new URL(base).origin;
  const pinned = document.head.querySelector(`meta[${PINNED}]`);
  if (pinned) return pinned.getAttribute(PINNED) === origin;
  const policy = serverPolicy(base);
  if (!policy) return true;
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = policy;
  meta.setAttribute(PINNED, origin);
  document.head.prepend(meta);
  return true;
}
