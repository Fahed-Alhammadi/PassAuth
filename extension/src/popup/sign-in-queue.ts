/**
 * The approval queue's one rule of its own (pure; the rest is the web vault's `settleQueue`): a request on screen is
 * the same request while the list has its id with the same public key. Its `challenge` is sealed to the account
 * again at every listing (a fresh ephemeral key: other text, the same plaintext), so its text is never compared: the
 * shown request keeps the challenge it was frozen with, which still opens to the same proof.
 */
import type { SignInRequest } from "@web/lib/device-login";

/**
 * `requests` as the queue should compare them: the listed copy of the shown request (same id, same public key) carries
 * the challenge the shown one was frozen with, so a re-sealed challenge never closes its sheet. Another key under the
 * same id is left as listed: the sheet closes ("changed").
 */
export function keepFrozenChallenge<R extends SignInRequest>(requests: R[], shown: SignInRequest | null): R[] {
  if (!shown) return requests;
  return requests.map((r) => (r.id === shown.id && r.publicKey === shown.publicKey && r.challenge !== shown.challenge ? { ...r, challenge: shown.challenge } : r));
}
