/**
 * Authenticator keys from otpauth links, like the iOS app's `OtpAuth`. The key is stored as the whole
 * `otpauth://totp/…` URI (what the web vault's editor stores); the core's TOTP parser (`totpCode`) has
 * the last word, so anything accepted here produces codes.
 */
import { totpCode } from "@web/lib/vault";

export interface OtpKey {
  /** The `otpauth://totp/…` URI for the login's `totp` field. */
  value: string;
  issuer: string;
  account: string;
}

export type OtpParse = { key: OtpKey } | { problem: string };

const PREFIX = "otpauth://totp/";
/** The core parses `digits` as u32 (6–10) and `period` as a non-zero u64. */
const U64_MAX = 18446744073709551615n;
const isUint = (v: string) => /^\+?\d+$/.test(v);

/** "Example (alice@example.com)". */
export function otpLabel(key: OtpKey) {
  if (key.issuer && key.account) return `${key.issuer} (${key.account})`;
  return key.issuer || key.account;
}

/** Percent-decoding without turning "+" into a space. */
function decode(s: string) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Parse an `otpauth://` or `apple-otpauth://` link. */
export function parseOtpLink(link: string): OtpParse {
  let text = link.trim();
  const scheme = text.slice(0, text.indexOf(":")).toLowerCase();
  if (scheme === "apple-otpauth") text = "otpauth" + text.slice(scheme.length);
  const lower = text.toLowerCase();
  if (lower.startsWith("otpauth-migration:")) {
    return { problem: "This is an authenticator app's export of several accounts. Scan the QR code a website shows when you set up two-step login." };
  }
  if (lower.startsWith("otpauth://hotp/")) {
    return { problem: "This is a counter-based (HOTP) key. PassAuth supports time-based (TOTP) keys only." };
  }
  if (!lower.startsWith(PREFIX)) {
    return { problem: "This isn't an authenticator key. Look for a QR code or key on the website's two-step login setup page." };
  }
  // The core matches the prefix exactly.
  const uri = PREFIX + text.slice(PREFIX.length);
  const rest = uri.slice(PREFIX.length);
  const q = rest.indexOf("?");
  const path = q < 0 ? rest : rest.slice(0, q);
  const query = q < 0 ? "" : rest.slice(q + 1);

  let secret: string | null = null;
  let issuerParam = "";
  for (const pair of query.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const k = (eq < 0 ? pair : pair.slice(0, eq)).toLowerCase();
    const v = eq < 0 ? "" : pair.slice(eq + 1);
    if (k === "secret") secret = v;
    else if (k === "issuer") issuerParam = decode(v);
    else if (k === "algorithm" && !["SHA1", "SHA256", "SHA512"].includes(v.toUpperCase())) {
      return { problem: `This key uses an unsupported algorithm (${v}).` };
    } else if (k === "digits" && !(isUint(v) && +v >= 6 && +v <= 10)) {
      return { problem: `This key asks for an unsupported number of digits (${v}).` };
    } else if (k === "period" && !(isUint(v) && BigInt(v.replace("+", "")) > 0n && BigInt(v.replace("+", "")) <= U64_MAX)) {
      return { problem: `This key has an invalid period (${v}).` };
    }
  }
  if (secret === null) return { problem: "This QR code has no secret key in it." };
  try {
    totpCode(uri, Date.now() / 1000);
  } catch {
    return { problem: "The secret key in this QR code isn't valid." };
  }

  const label = decode(path);
  const colon = label.indexOf(":");
  const issuer = colon < 0 ? issuerParam : issuerParam || label.slice(0, colon).trim();
  const account = (colon < 0 ? label : label.slice(colon + 1)).trim();
  return { key: { value: uri, issuer, account } };
}
