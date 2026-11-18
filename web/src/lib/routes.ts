/**
 * The web vault's sign-in address and the rules around it (user rule, 2026-11-18):
 * - the sign-in page lives at the site root (`https://<server>/`), never at `/login`; `/login` only redirects there;
 * - a signed-out visit to any app page lands on the root and returns to that page after sign-in;
 * - after Log out the address is the root (never left on `/vault`, `/settings`…);
 * - signed in (locked or unlocked), the root opens the vault.
 */
export const SIGN_IN_PATH = "/";
/** Where sign-in goes when no page asked for it. */
export const HOME_PATH = "/vault";

/** The router state a signed-out visit to `pathname` carries to the sign-in page: where to return to. */
export const signedOutState = (pathname: string): { from: string } => ({ from: pathname });

/**
 * Where to go after signing in: the page that sent the visitor to the sign-in page (`state.from`), only within the
 * app, and never the sign-in page itself (the root, or its old address `/login`); otherwise the vault.
 */
export function afterSignIn(state: unknown): string {
  const from = (state as { from?: unknown } | null)?.from;
  if (typeof from !== "string" || !from.startsWith("/") || from.startsWith("//") || from.includes("\\")) return HOME_PATH;
  const path = from.split(/[?#]/)[0].replace(/\/+$/, "");
  return path === "" || path === "/login" ? HOME_PATH : from;
}
