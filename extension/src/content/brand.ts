/**
 * Look of the little PassAuth UI that is drawn inside web pages themselves (the
 * toast, the shadow under PassAuth's frames). It lives in closed shadow roots,
 * where the shared stylesheet doesn't reach, so the brand palette is repeated
 * here once, as tokens. Everything with vault data in it (inline menu, save
 * prompt) is an extension page in a frame instead, styled by the shared
 * stylesheet; nothing here may show vault data.
 */

/** PassAuth mark (assets/passauth-logo.svg). Gradient ids are per closed shadow root. */
export const logoSvg = (size: number) => `
<svg width="${Math.round((size * 128) / 144)}" height="${size}" viewBox="0 0 128 144" aria-hidden="true">
  <defs><linearGradient id="g" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stop-color="#082052"/><stop offset=".52" stop-color="#0866ED"/><stop offset="1" stop-color="#23D5F4"/></linearGradient></defs>
  <path d="M64 5 111 27Q117 30 117 39V82Q117 114 64 139 11 114 11 82V39Q11 30 17 27Z" fill="url(#g)"/>
  <path d="M42 30H70C95 30 103 45 103 62 103 82 89 96 66 96H55V121L38 112V30ZM55 48V78H67C79 78 84 72 84 63 84 54 79 48 67 48Z" fill="#fff" fill-rule="evenodd"/>
  <circle cx="69" cy="59" r="5" fill="#082052"/><path d="M66.8 62H71.2L74 71H64Z" fill="#082052"/>
</svg>`;

const stroke = (d: string, size = 16) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${d}"/></svg>`;
export const closeSvg = stroke("M6 6l12 12M18 6L6 18", 18);
export const plusSvg = stroke("M12 5v14M5 12h14", 18);

/** The one elevation of floating PassAuth surfaces, for frames placed in a page (the page's own theme is unknown there). */
export const panelShadow = "0 2px 6px rgb(8 32 82 / .08), 0 16px 40px rgb(8 32 82 / .16)";

/**
 * `.b` is the toast; `data-theme` on it carries the user's light/dark choice
 * ("system" follows the OS). Generic font families only: a font a page could
 * define itself (@font-face applies inside shadow trees too) would let it
 * measure the text.
 */
export const toastCss = `
  .b { --bg: #fff; --ink: #0b1a3a; --line: #d6dfec; --shadow: ${panelShadow};
       box-sizing: border-box; display: flex; align-items: center; gap: 12px; max-width: 340px; padding: 12px 16px;
       font: 500 13px/20px system-ui, sans-serif; text-align: left; letter-spacing: 0; overflow-wrap: anywhere;
       color: var(--ink); background: var(--bg); border: 1px solid var(--line); border-radius: 12px; box-shadow: var(--shadow);
       color-scheme: light; animation: in 180ms cubic-bezier(.2, .7, .2, 1); }
  @media (prefers-color-scheme: dark) { .b:not([data-theme="light"]) { --bg: #111b2e; --ink: #e7edf7; --line: #2c3b57; --shadow: 0 2px 6px rgb(0 0 0 / .4), 0 16px 40px rgb(0 0 0 / .45); color-scheme: dark; } }
  .b[data-theme="dark"] { --bg: #111b2e; --ink: #e7edf7; --line: #2c3b57; --shadow: 0 2px 6px rgb(0 0 0 / .4), 0 16px 40px rgb(0 0 0 / .45); color-scheme: dark; }
  svg { flex: none; display: block; }
  @keyframes in { from { opacity: 0; transform: translateY(-4px); } }
  @media (prefers-reduced-motion: reduce) { .b { animation: none; } }
`;
