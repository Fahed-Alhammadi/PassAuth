/** Emergency Kit (what a user needs to sign in on a new device) and the file download helper. */

/** Save `content` as a file. The link is attached to the page and revoked later, which every browser needs to start the download. */
export function downloadFile(filename: string, content: string, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export interface KitInfo {
  email: string;
  secretKey: string | null;
  server?: string;
}

/** A printable page: server, email, Secret Key (if any) and a line to write the master password on. */
export function emergencyKitHtml({ email, secretKey, server = location.origin }: KitInfo): string {
  const created = new Date().toLocaleDateString(undefined, { dateStyle: "long" });
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PassAuth Emergency Kit</title>
<style>
  :root { color-scheme: light; }
  body { font: 15px/1.5 "IBM Plex Sans", system-ui, sans-serif; color: #0b1a3a; background: #fff; margin: 0; padding: 32px 16px; }
  main { max-width: 640px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }
  h1 { margin: 0; font-size: 1.6rem; }
  p { margin: 0; }
  .muted { color: #5a6a85; }
  dl { margin: 0; border: 1px solid #8494ad; border-radius: 10px; }
  dl > div { padding: 14px 16px; border-bottom: 1px solid #d6dfec; }
  dl > div:last-child { border-bottom: 0; }
  dt { font-size: .8rem; color: #5a6a85; text-transform: uppercase; letter-spacing: .04em; }
  dd { margin: 4px 0 0; font-size: 1.05rem; overflow-wrap: anywhere; }
  .mono { font-family: "IBM Plex Mono", ui-monospace, monospace; letter-spacing: .04em; }
  .write { height: 40px; border-bottom: 1px solid #0b1a3a; }
  .warn { padding: 12px 14px; border-radius: 8px; background: #fdf0dc; color: #6b4000; }
  button { font: inherit; font-weight: 600; padding: 10px 18px; border-radius: 6px; border: 0; background: #0866ed; color: #fff; cursor: pointer; align-self: flex-start; }
  @media print { button { display: none; } body { padding: 0; } }
</style></head>
<body><main>
  <h1>PassAuth Emergency Kit</h1>
  <p class="muted">Created ${esc(created)}</p>
  <p>Print this page or keep it somewhere safe and offline, such as a drawer or a safe. You need it to sign in on a new device. Nobody, not even your server administrator, can recover your master password${secretKey ? " or Secret Key" : ""} for you.</p>
  <dl>
    <div><dt>Server</dt><dd class="mono">${esc(server)}</dd></div>
    <div><dt>Email</dt><dd>${esc(email)}</dd></div>
    ${
      secretKey
        ? `<div><dt>Secret Key</dt><dd class="mono">${esc(secretKey)}</dd></div>`
        : `<div><dt>Secret Key</dt><dd>None. Your master password alone opens your vault.</dd></div>`
    }
    <div><dt>Master password</dt><dd class="write"></dd></div>
  </dl>
  <p class="warn">Write your master password by hand only if this kit is stored somewhere nobody else can reach.</p>
  <button type="button" onclick="print()">Print</button>
</main></body></html>`;
}

export function downloadEmergencyKit(info: KitInfo) {
  downloadFile("PassAuth Emergency Kit.html", emergencyKitHtml(info), "text/html;charset=utf-8");
}

/** Open the print dialog for the kit, without leaving the vault (a hidden frame holds the page). */
export function printEmergencyKit(info: KitInfo) {
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.tabIndex = -1;
  frame.style.cssText = "position:fixed;width:0;height:0;border:0;opacity:0;pointer-events:none";
  frame.srcdoc = emergencyKitHtml(info);
  frame.onload = () => {
    try {
      frame.contentWindow?.focus();
      frame.contentWindow?.print();
    } finally {
      setTimeout(() => frame.remove(), 60_000);
    }
  };
  document.body.append(frame);
}
