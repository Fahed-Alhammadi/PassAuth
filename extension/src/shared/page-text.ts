/**
 * Text that PassAuth shows inside a web page (toasts): the page can read it, so it must never contain vault data
 * (item names, user names, saved websites). `PageSafeText` is a branded string that only these helpers make, and the
 * toast command takes nothing else, so a vault value can't reach a page by accident: it would have to be wrapped on
 * purpose.
 */

declare const pageSafe: unique symbol;

/** A string that may be shown inside a web page. */
export type PageSafeText = string & { readonly [pageSafe]: true };

/**
 * Page-safe text from a template: the literal parts are PassAuth's own wording; the values must be page-safe
 * already (or numbers). `pageText\`Login saved for ${hostText(host)}.\``
 */
export function pageText(strings: TemplateStringsArray, ...values: (PageSafeText | number)[]): PageSafeText {
  let out = strings[0] ?? "";
  values.forEach((v, i) => {
    out += String(v) + (strings[i + 1] ?? "");
  });
  return out as PageSafeText;
}

/**
 * A host name taken from the address of the page itself (the tab or the sending frame), which the page knows
 * anyway. Never use it for a website saved in the vault.
 */
export const hostText = (host: string): PageSafeText => host as PageSafeText;
