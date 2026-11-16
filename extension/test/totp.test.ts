// S2: the popup counts verification codes down itself (which requests restart the vault timeout: router.test.ts).

import { expect, test } from "vitest";
import { secondsLeft, totpExpiry } from "../src/shared/totp";

test("totpExpiry: the end of the code's time step, on whole multiples of the period", () => {
  expect(totpExpiry(30, 0)).toBe(30_000);
  expect(totpExpiry(30, 29_999)).toBe(30_000);
  expect(totpExpiry(30, 30_000)).toBe(60_000);
  expect(totpExpiry(60, 1_700_000_012_345)).toBe(1_700_000_040_000);
});

test("secondsLeft: what the ring shows, the same as the core's `remaining` at that second", () => {
  const expires = totpExpiry(30, 1_000_000_000_000);
  // core: remaining = period - t % period, with t in whole seconds.
  for (const at of [1_000_000_000_000, 1_000_000_000_400, 1_000_000_009_999, 1_000_000_019_000]) {
    const t = Math.floor(at / 1000);
    expect(secondsLeft(expires, at)).toBe(30 - (t % 30));
  }
  expect(secondsLeft(expires, expires)).toBe(0);
  expect(secondsLeft(expires, expires + 5000)).toBe(0);
});
