// The popup's approval queue (popup/sign-in-queue.ts with the web vault's settleQueue): the shown request is the same
// request while the list has its id with the same public key. The server seals the challenge again at every listing
// (other text, same plaintext), so the challenge's text never closes the sheet; another key does.

import { EMPTY_QUEUE, type SignInRequest, settleQueue } from "@web/lib/device-login";
import { expect, test } from "vitest";
import { keepFrozenChallenge } from "../src/popup/sign-in-queue";

const KEY = "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA";
const OTHER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const NOW = 1_700_000_000;
const req = (id: string, extra: Partial<SignInRequest> = {}): SignInRequest => ({
  id,
  publicKey: KEY,
  challenge: `challenge-${id}`,
  deviceName: "Firefox on Linux",
  deviceKind: "web",
  client: null,
  ip: null,
  createdAt: NOW - 10,
  expiresAt: NOW + 600,
  ...extra,
});

/** The queue after a listing, as the popup works it out (keepFrozenChallenge, then settleQueue). */
function relist(shown: SignInRequest | null, requests: SignInRequest[]) {
  const next = { ...EMPTY_QUEUE, shown, requests: keepFrozenChallenge(requests, shown) };
  return settleQueue(next, NOW).queue;
}

test("same key, the challenge sealed again (other text): the sheet stays, with the challenge it was frozen with", () => {
  const first = relist(null, [req("r1")]);
  expect(first.shown?.id).toBe("r1");
  const again = relist(first.shown, [req("r1", { challenge: "challenge-r1-sealed-again" })]);
  expect(again.shown).toBe(first.shown);
  expect(again.shown?.challenge).toBe("challenge-r1");
  expect(again.notice).toBe(null);
});

test("another key under the same id: the sheet closes with the 'changed' note, and the request is put off", () => {
  const first = relist(null, [req("r1")]);
  const changed = relist(first.shown, [req("r1", { publicKey: OTHER, challenge: "challenge-r1-theirs" })]);
  expect(changed.shown).toBe(null);
  expect(changed.notice).toStrictEqual({ kind: "changed" });
  expect(changed.putOff.has("r1")).toBe(true);
});

test("only the shown request's copy carries the frozen challenge; the others are left as listed", () => {
  const shown = req("r1");
  const out = keepFrozenChallenge([req("r1", { challenge: "new" }), req("r2", { challenge: "new-2" }), req("r1", { publicKey: OTHER, challenge: "theirs" })], shown);
  expect(out.map((r) => r.challenge)).toStrictEqual(["challenge-r1", "new-2", "theirs"]);
  expect(keepFrozenChallenge([req("r1", { challenge: "x" })], null)[0]?.challenge).toBe("x");
});
