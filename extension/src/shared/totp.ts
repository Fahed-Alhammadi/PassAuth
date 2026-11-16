/**
 * Verification-code timing shared by the background (which makes the code) and
 * the popup (which counts it down without asking again every second).
 * Unit-tested in test/activity.test.ts.
 */

/** When a code made at `nowMs` stops being valid: the end of its time step (codes change on whole multiples of `period` seconds). */
export const totpExpiry = (period: number, nowMs: number): number => (Math.floor(nowMs / 1000 / period) + 1) * period * 1000;

/** Whole seconds left until `expires`, as the countdown shows them (never below 0). */
export const secondsLeft = (expires: number, nowMs: number): number => Math.max(0, Math.ceil((expires - nowMs) / 1000));
