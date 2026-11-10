/**
 * Where a new passkey can be saved ("Save in" in the confirmation window).
 * Pure (no chrome, no vault), unit-tested in test/passkey-targets.test.mjs.
 */

/** A vault login, reduced to what choosing a place for a passkey needs. */
export interface PasskeyLogin {
  id: string;
  name: string;
  username: string;
  /** The login's website addresses, as saved (scheme optional). */
  urls: string[];
  /** In a vault the user can edit. */
  writable: boolean;
  /** In the user's own vault, not one somebody shared with them. */
  personal: boolean;
  /** Name of the vault, shown when it is a shared one. */
  vault?: string;
}

export interface PasskeyTarget {
  id: string;
  name: string;
  username: string;
  /** Preselected: the user's own login for this exact site. Never a login in a shared vault. */
  preferred: boolean;
  /** Set when the login lives in a shared vault: that vault's name. */
  vault?: string;
}

/** Hostnames of website addresses (scheme optional), lowercase, without a trailing dot. */
export function hostsOf(urls: string[]): string[] {
  return urls.flatMap((url) => {
    try {
      return [new URL(url.includes("://") ? url : `https://${url}`).hostname.toLowerCase().replace(/\.$/, "")];
    } catch {
      return [];
    }
  });
}

/**
 * Logins a new passkey can be saved in: ones the user can edit whose website is
 * this exact host, the RP ID, or a subdomain of the RP ID (where the passkey
 * also works). Never just "the same base domain": cloudy.example.com and
 * bazarr.example.com are different sites.
 *
 * Order: the user's own logins first (this exact host, then a matching user
 * name, then by name), logins in shared vaults after them. Only an own login
 * for the exact host is `preferred` (preselected): anyone on the server can
 * share a vault with the user and put a login for the site in it, and a
 * passkey saved there is handed to that vault's other members. A shared login
 * can still be picked on purpose; its row names the vault.
 */
export function passkeySaveTargets(logins: PasskeyLogin[], host: string, rpId: string, userName: string, displayName: string): PasskeyTarget[] {
  const rp = rpId.toLowerCase();
  const names = [userName, displayName].map((n) => n.trim().toLowerCase()).filter(Boolean);
  const score = (l: PasskeyLogin) => {
    const user = l.username.trim().toLowerCase();
    return (l.personal ? 4 : 0) + (hostsOf(l.urls).includes(host) ? 2 : 0) + (user && names.some((n) => n === user || n === user.split("@")[0]) ? 1 : 0);
  };
  return logins
    .filter((l) => l.writable && hostsOf(l.urls).some((h) => h === host || h === rp || h.endsWith(`.${rp}`)))
    .sort((a, b) => score(b) - score(a) || a.name.localeCompare(b.name))
    .map((l) => ({
      id: l.id,
      name: l.name,
      username: l.username,
      preferred: l.personal && hostsOf(l.urls).includes(host),
      ...(l.personal ? {} : { vault: l.vault || "Shared vault" }),
    }));
}
