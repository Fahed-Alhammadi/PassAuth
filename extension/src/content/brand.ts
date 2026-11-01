/** PassAuth mark for in-page UI (assets/passauth-logo.svg). Gradient ids are per closed shadow root. */
export const logoSvg = (size: number) => `
<svg width="${Math.round((size * 128) / 144)}" height="${size}" viewBox="0 0 128 144" aria-hidden="true">
  <defs><linearGradient id="g" x1="0" y1="1" x2="1" y2="0"><stop offset="0" stop-color="#082052"/><stop offset=".52" stop-color="#0866ED"/><stop offset="1" stop-color="#23D5F4"/></linearGradient></defs>
  <path d="M64 5 111 27Q117 30 117 39V82Q117 114 64 139 11 114 11 82V39Q11 30 17 27Z" fill="url(#g)"/>
  <path d="M42 30H70C95 30 103 45 103 62 103 82 89 96 66 96H55V121L38 112V30ZM55 48V78H67C79 78 84 72 84 63 84 54 79 48 67 48Z" fill="#fff" fill-rule="evenodd"/>
  <circle cx="69" cy="59" r="5" fill="#082052"/><path d="M66.8 62H71.2L74 71H64Z" fill="#082052"/>
</svg>`;

export const panelCss = `
  .b { font: 14px/1.45 system-ui, sans-serif; background: #0b1a3a; color: #e7edf7; border-radius: 12px;
       box-shadow: 0 12px 32px rgb(0 0 0 / .3); padding: 16px; display: grid; gap: 12px; }
  .t { display: flex; gap: 10px; align-items: center; font-weight: 600; }
  .t svg { flex: none; }
  p { margin: 0; color: #b3c0d6; overflow-wrap: anywhere; }
  button { font: inherit; border-radius: 6px; padding: 7px 12px; cursor: pointer; border: 1px solid #3a4a68; background: transparent; color: #e7edf7; }
  button.p { background: #0866ed; border-color: #0866ed; color: #fff; font-weight: 600; }
  button:focus-visible { outline: 2px solid #4aa3ff; outline-offset: 2px; }
`;
