/** Offline changes (ARCHITECTURE "Offline changes"): words both the background and the popup show. */

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The warning before Log out, Change server or removing the account while changes wait. */
export const lostText = (n: number) => `${plural(n, "change hasn't", "changes haven't")} been sent and will be lost.`;

/** The confirmation of "Discard this change". */
export const DISCARD_TEXT = "Your change to this item will be lost.";
