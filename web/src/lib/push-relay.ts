/**
 * The push relay address the admin types (Admin → Features): the same rules the server applies
 * (`crates/server/src/push.rs` `check_relay_url`), so the page can say what's wrong before saving.
 */

/** An `https://` address with a host, or `http://` to this machine (`localhost`, `127.0.0.1`, `[::1]`); no user name, query or fragment. */
export function relayUrlProblem(input: string): string | null {
  const s = input.trim().replace(/\/+$/, "");
  if (!s) return "Enter the relay's address, such as https://push.example.com.";
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return "Enter a full address that starts with https://, such as https://push.example.com.";
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  const schemeOk = url.protocol === "https:" ? url.hostname !== "" : url.protocol === "http:" && local;
  if (!schemeOk) return "The relay's address must start with https://.";
  if (url.username || url.password || url.search || url.hash) return "Leave out user names, ? and # parts.";
  return null;
}

/** The address as the server saves it: trimmed, without a trailing slash. */
export function normalizeRelayUrl(input: string): string {
  return input.trim().replace(/\/+$/, "");
}
