/**
 * PassAuth's main content script (content.js: isolated world, every frame, document_idle; also about:blank and
 * srcdoc frames a page writes itself, which stand for the page's own origin: origin.ts). The passkey bridge is a
 * separate, tiny document_start script (bridge.ts).
 * - Fills logins, one-time codes, cards and identities only on explicit request from the background, sent to this
 *   document alone, and only while it is still at the origin the background checked (fill.ts).
 * - Offers to save credentials after a submit that seems to have worked (capture.ts, save-prompt.ts).
 * - Shows the inline menu on login, sign-up, one-time-code, card and identity fields (inline.ts).
 * - Tells the right-click menu whether the field the user is in is a password field (context-field.ts).
 */
import { type ContentCommandApi, callContent, type Message, type ResOf } from "../shared/protocol";
import { installCapture } from "./capture";
import { contextFieldInfo, installContextField } from "./context-field";
import { hasFields, Scan } from "./fields";
import { fillCard, fillGenerated, fillIdentity, fillLogin } from "./fill";
import { closeInlineMenu, inlineMenuOff, installInlineMenu, menuTouched, returnFocus } from "./inline";
import { pageUrl } from "./origin";
import { closeSavePrompt, resizeSavePrompt, savePromptTouched, showSavePrompt } from "./save-prompt";
import { showToast } from "./toast";

/**
 * A request from the page side that fails changes nothing on the page: the extension was reloaded or updated (this
 * script is then cut off from it) or the background refused. Nothing to show or retry.
 */
const ignore = () => {};

installCapture();
installInlineMenu();
installContextField();

/** What the background can ask of this frame (shared/protocol.ts `ContentCommandApi`). */
const commands: { [K in keyof ContentCommandApi]: (cmd: Message<ContentCommandApi, K>) => ResOf<ContentCommandApi, K> } = {
  fill: (cmd) => ({ filled: fillLogin(cmd) }),
  "fill:offer": (cmd) => {
    // No secrets and no websites in an offer: a frame with a matching form claims it, and the background checks the frame.
    const url = pageUrl();
    if (!url || (cmd.kind === "card" && !url.startsWith("https:"))) return;
    if (hasFields(new Scan(), cmd.kind ?? "login")) callContent("page:fillClaim", { token: cmd.token }).catch(ignore);
  },
  "fill:card": (cmd) => ({ filled: fillCard(cmd) }),
  "fill:identity": (cmd) => ({ filled: fillIdentity(cmd) }),
  "fill:generated": (cmd) => fillGenerated(cmd.password, cmd.origin, cmd.field === "context" ? "context" : "menu"),
  "context:field": () => contextFieldInfo(),
  showSave: (cmd) => showSavePrompt(cmd),
  "save:size": (cmd) => resizeSavePrompt(cmd.height),
  "save:close": () => closeSavePrompt(),
  "save:touch": (cmd) => savePromptTouched(String(cmd.nonce)),
  toast: (cmd) => showToast(cmd.text, cmd.theme),
  "inline:close": (cmd) => {
    closeInlineMenu();
    if (cmd.refocus && typeof cmd.nonce === "string") returnFocus(cmd.nonce);
  },
  "inline:return": (cmd) => returnFocus(String(cmd.nonce)),
  "inline:touch": (cmd) => menuTouched(String(cmd.nonce)),
  "inline:off": () => inlineMenuOff(),
};

// Only PassAuth's own extension can send to a content script (chrome.tabs.sendMessage). Every command is answered
// (null when it has no answer), so the background can tell "received" from "no content script here yet".
chrome.runtime.onMessage.addListener((cmd: Message<ContentCommandApi>, _sender, respond) => {
  if (!Object.hasOwn(commands, cmd?.type)) return;
  const answer = (commands[cmd.type] as (c: Message<ContentCommandApi>) => unknown)(cmd);
  respond(answer === undefined ? null : answer);
});
