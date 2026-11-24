/**
 * Requests from PassAuth's pages framed inside web pages: the inline menu (inline-menu.html) and the save prompt
 * (save-prompt.html). Each only gets the few requests it needs, each tied to its nonce (nonces.ts). The page around
 * the frame can post to it, so what it sends is checked (`parse`) like content-script messages.
 */

import { MAX_PASSWORD, MAX_USERNAME } from "../../shared/limits";
import type { InlineFrameApi, SaveFrameApi } from "../../shared/protocol";
import type { SaveEdits } from "../../shared/types";
import { all, isRecord, num, oneOf, optional, text, token, yesNo } from "../checks";
import { close, fillFromMenu, generate, hide, items, touched as menuTouched, newItem, returnFocus, unlockFromMenu } from "../inline-menu";
import type { CheckedHandlers } from "../router";
import { answer, details, offer, touched as promptTouched, resize } from "../save-prompt";
import type { SenderKind } from "../senders";

const INLINE: readonly SenderKind[] = ["inline"];
const SAVE: readonly SenderKind[] = ["save"];

const nonceOnly = (m: Record<string, unknown>) => all({ nonce: token(m.nonce) });

export const inlineHandlers = {
  "inline:items": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => items(sender, nonce) },
  // A fill restarts the vault timeout itself (inline-menu.ts): opening or closing the menu must not.
  "inline:fill": { from: INLINE, parse: (m) => all({ nonce: token(m.nonce), id: text(m.id, 128) }), run: ({ nonce, id }, sender) => fillFromMenu(sender, nonce, id) },
  "inline:close": {
    from: INLINE,
    parse(m) {
      const req = all({ nonce: token(m.nonce) });
      const refocus = optional(m.refocus, yesNo);
      return req && refocus !== null ? { ...req, ...(refocus ? { refocus } : {}) } : null;
    },
    run: ({ nonce, refocus }, sender) => close(sender, nonce, refocus === true),
  },
  // From the menu frame, sent on to the field's document: it never posts to the page itself (frame-channel.ts).
  "inline:return": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => returnFocus(sender, nonce) },
  "inline:touch": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => menuTouched(sender, nonce) },
  "inline:unlock": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => unlockFromMenu(sender, nonce) },
  // A generated password is the user at work: generate() restarts the vault timeout itself.
  "inline:generate": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => generate(sender, nonce) },
  "inline:new": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => newItem(sender, nonce) },
  "inline:hide": { from: INLINE, parse: nonceOnly, run: ({ nonce }, sender) => hide(sender, nonce) },
} satisfies CheckedHandlers<InlineFrameApi>;

const ACCEPT = ["save", "never", "dismiss"] as const;

/** The "Edit" form's values: a password (as the save rule needs one), nothing longer than a typed login may be. */
function saveEdits(v: unknown): SaveEdits | null {
  if (!isRecord(v)) return null;
  const edits = all({ name: text(v.name, 120), username: text(v.username, MAX_USERNAME), password: text(v.password, MAX_PASSWORD) });
  return edits?.password ? edits : null;
}

export const saveHandlers = {
  "save:offer": { from: SAVE, parse: nonceOnly, run: ({ nonce }, sender) => offer(sender, nonce) },
  "save:answer": {
    from: SAVE,
    parse(m) {
      const req = all({ nonce: token(m.nonce), accept: oneOf(m.accept, ACCEPT) });
      if (!req) return null;
      const target = optional(m.target, (v) => text(v, 128));
      // Edits only come with "save".
      const edits = req.accept === "save" ? optional(m.edits, saveEdits) : m.edits === undefined ? undefined : null;
      if (target === null || edits === null) return null;
      return { ...req, ...(target !== undefined ? { target } : {}), ...(edits ? { edits } : {}) };
    },
    run: ({ nonce, accept, target, edits }, sender) => answer(sender, nonce, accept, target, edits),
  },
  "save:details": { from: SAVE, parse: nonceOnly, run: ({ nonce }, sender) => details(sender, nonce) },
  "save:resize": { from: SAVE, parse: (m) => all({ nonce: token(m.nonce), height: num(m.height) }), run: ({ nonce, height }, sender) => resize(sender, nonce, height) },
  "save:touch": { from: SAVE, parse: nonceOnly, run: ({ nonce }, sender) => promptTouched(sender, nonce) },
} satisfies CheckedHandlers<SaveFrameApi>;
