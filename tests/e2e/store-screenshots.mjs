// Chrome Web Store assets: runs the real extension with demo data (fictional
// brands) and renders 1280×800 screenshots plus promo tiles into docs/store/.
//
//   node tests/e2e/store-screenshots.mjs "$PWD/extension/dist"
//
// Needs a throwaway server on PASSAUTH_URL (default http://localhost:8091) and
// the test site on http://localhost:8099 (see tests/e2e/README.md).
import { spawn } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [, , EXT] = process.argv;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = join(ROOT, "docs/store");
const RAW = mkdtempSync(join(process.env.E2E_TMP ?? tmpdir(), "store-raw-"));
const SERVER = process.env.PASSAUTH_URL ?? "http://localhost:8091";
// The demo shop is served by the test site under a fictional name (mapped to 127.0.0.1 below).
const SITE = "http://shop.copperleaf.example:8099/demo-shop.html";
const CHROMIUM = process.env.CHROMIUM ?? "/Applications/Chromium.app/Contents/MacOS/Chromium";
const EMAIL = `alex${Date.now()}@example.com`;
const PW = "copper kettle harbour lantern 9";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(join(OUT, "screenshots"), { recursive: true });

const profile = mkdtempSync(join(process.env.E2E_TMP ?? tmpdir(), "chromium-store-"));
const proc = spawn(CHROMIUM, ["--headless=new", "--remote-debugging-port=9447", `--user-data-dir=${profile}`, `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--no-first-run", "--hide-scrollbars", "--allow-file-access-from-files", "--host-resolver-rules=MAP shop.copperleaf.example 127.0.0.1", "--window-size=1280,900", "about:blank"], { stdio: "ignore" });
let ver;
for (let i = 0; i < 60 && !ver; i++) {
  try {
    ver = await (await fetch("http://127.0.0.1:9447/json/version")).json();
  } catch {
    await sleep(200);
  }
}
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let n = 0;
const pending = new Map();
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) {
    const p = pending.get(m.id);
    pending.delete(m.id);
    m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result);
  }
});
const cmd = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = ++n;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });

async function attach(targetId) {
  const { sessionId } = await cmd("Target.attachToTarget", { targetId, flatten: true });
  await cmd("Runtime.enable", {}, sessionId);
  const ev = async (expr) => {
    const r = await cmd("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };
  const waitFor = async (expr, t = 30000) => {
    const s = Date.now();
    while (Date.now() - s < t) {
      try {
        if (await ev(expr)) return;
      } catch {}
      await sleep(150);
    }
    throw new Error(`timeout: ${expr}`);
  };
  const shot = async (file, clip) => {
    const r = await cmd("Page.captureScreenshot", { format: "png", ...(clip ? { clip: { ...clip, scale: 1 } } : {}) }, sessionId);
    writeFileSync(join(RAW, file), Buffer.from(r.data, "base64"));
  };
  const look = (width, height, scale = 2) =>
    Promise.all([
      cmd("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: scale, mobile: false }, sessionId),
      cmd("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] }, sessionId),
    ]);
  const fillLabel = (label, value) =>
    ev(`(() => { const l=[...document.querySelectorAll('label')].find(l=>l.querySelector('span')?.textContent.trim()===${JSON.stringify(label)}); const el=l.querySelector('input,textarea'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input',{bubbles:true})); })()`);
  const click = (text) => ev(`(() => { const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}); if(!b) throw new Error('no button ${text}'); b.click(); })()`);
  return { sessionId, targetId, ev, waitFor, shot, look, fillLabel, click };
}
const page = async (url, background = false) => attach((await cmd("Target.createTarget", { url, background })).targetId);
const step = async (name, fn) => {
  process.stdout.write(`- ${name} … `);
  await fn();
  console.log("ok");
};

// ------------------------------------------------------------ demo data

const login = (name, username, password, url, extra = {}) => ({
  name, notes: "", favorite: false, folder: null, tags: [], card: null, identity: null, ssh_key: null, fields: [], password_history: [], created_at: 0, updated_at: 0,
  login: { username, password, urls: [{ url, match: "default" }], totp: null, passkeys: [] },
  ...extra,
});
const DEMO = [
  login("Copperleaf", "alex@example.com", "Rq7!tw-Kepler-88", "http://shop.copperleaf.example", { favorite: true, folder: "Shopping" }),
  { ...login("Harbor Bank", "alex.morgan", "vX9$gL2#pQ8mZr4!", "https://online.harborbank.example", { favorite: true, folder: "Finance" }), notes: "Branch: Marina Walk" },
  login("Lumen Mail", "alex@lumen.example", "lantern-orbit-cedar-41", "https://mail.lumen.example", { folder: "Personal" }),
  login("Pinecrest Cloud", "alex.morgan@work.example", "Pc-2024!stable-river", "https://console.pinecrest.example", { folder: "Work" }),
  login("Atlas Travel", "alexmorgan", "atlas-Compass-73!", "https://atlastravel.example", { folder: "Personal" }),
  login("Orbit Chat", "alex.m", "0rbit!signal-Quartz", "https://app.orbitchat.example", { folder: "Work" }),
  login("Quill Notes", "alex@example.com", "quill-Meadow-2219", "https://quillnotes.example", { folder: "Work" }),
  login("Fern Health", "AM-40211", "Fern#harbour-6610", "https://portal.fernhealth.example", { folder: "Personal" }),
  {
    name: "Harbor Bank Visa", notes: "", favorite: false, folder: "Finance", tags: [], login: null, identity: null, ssh_key: null, fields: [], password_history: [], created_at: 0, updated_at: 0,
    card: { cardholder_name: "Alex Morgan", brand: "Visa", number: "4111 1111 1111 1111", exp_month: "08", exp_year: "2029", code: "123" },
  },
  {
    name: "Home Wi-Fi", notes: "Network: Morgan-Home\nPassword: tidal-honey-ember-58", favorite: false, folder: "Personal", tags: [], login: null, card: null, identity: null, ssh_key: null, fields: [], password_history: [], created_at: 0, updated_at: 0,
  },
];
DEMO[1].login.totp = "JBSWY3DPEHPK3PXP";
DEMO[3].login.totp = "KRSXG5CTMVRXEZLU";

try {
  let extId;
  await step("extension loaded", async () => {
    for (let i = 0; i < 50 && !extId; i++) {
      const { targetInfos } = await cmd("Target.getTargets");
      extId = targetInfos.find((t) => t.type === "service_worker" && t.url.startsWith("chrome-extension://"))?.url.split("/")[2];
      if (!extId) await sleep(200);
    }
    if (!extId) throw new Error("service worker not found");
  });

  await step("demo account (Alex Morgan)", async () => {
    const w = await page(`${SERVER}/register`);
    await w.waitFor(`document.body.innerText.includes('Create your PassAuth account')`);
    await w.fillLabel("Email", EMAIL);
    await w.fillLabel("Your name", "Alex Morgan");
    await w.fillLabel("Master password", PW);
    await w.fillLabel("Confirm master password", PW);
    await w.click("Create account");
    await w.waitFor(`document.body.innerText.includes('Your vault is ready')`, 60000);
    await cmd("Target.closeTarget", { targetId: w.targetId });
  });

  const site = await page(SITE);
  await site.look(1000, 640);
  await site.waitFor(`!!document.getElementById('pass')`);

  // The popup page runs as a background tab next to the shop, so "the current site" is the shop.
  const popup = await page(`chrome-extension://${extId}/popup.html`, true);
  await popup.look(380, 600);
  const send = (msg) => popup.ev(`chrome.runtime.sendMessage(${JSON.stringify(msg)})`);
  await step("sign in and add demo items", async () => {
    await popup.waitFor(`document.body.innerText.includes('Connect to your PassAuth server')`);
    await popup.fillLabel("Server address", SERVER);
    await popup.click("Connect");
    await popup.waitFor(`document.body.innerText.includes('Sign in to PassAuth')`);
    await popup.fillLabel("Email", EMAIL);
    await popup.fillLabel("Master password", PW);
    await popup.click("Sign in");
    await popup.waitFor(`document.body.innerText.includes('All items')`, 60000);
    for (const item of DEMO) {
      const r = await send({ type: "createItem", item });
      if (!r.ok) throw new Error(r.error);
    }
    await send({ type: "settings", patch: { theme: "light" } });
  });

  await step("1: vault with autofill suggestion and badge", async () => {
    await popup.ev(`location.reload()`);
    await popup.waitFor(`document.body.innerText.includes('Autofill suggestions') && document.body.innerText.includes('Copperleaf')`, 30000);
    await sleep(600);
    await popup.shot("popup-vault.png");
    const tabId = await popup.ev(`chrome.tabs.query({ url: 'http://shop.copperleaf.example/*' }).then(t => t[0].id)`);
    const badge = await popup.ev(`chrome.action.getBadgeText({ tabId: ${tabId} })`);
    if (badge !== "1") throw new Error(`badge is "${badge}"`);
    await site.shot("page-shop.png");
  });

  await step("2: inline menu on the login field", async () => {
    await cmd("Target.activateTarget", { targetId: site.targetId });
    await site.ev(`document.getElementById('user').focus()`);
    await site.waitFor(`!!document.querySelector('passauth-inline-menu')`, 8000);
    let fr;
    for (let i = 0; i < 40 && !fr; i++) {
      fr = (await cmd("Target.getTargets")).targetInfos.find((t) => t.url.includes("inline-menu.html#"));
      if (!fr) await sleep(150);
    }
    const menu = await attach(fr.targetId);
    await menu.waitFor(`document.querySelectorAll('.row').length === 1`);
    await sleep(500);
    await site.shot("page-inline.png");
    await site.ev(`document.activeElement.blur(); document.body.click()`);
  });

  await step("3: item with verification code", async () => {
    await popup.ev(`[...document.querySelectorAll('.item-row .main')].find(b => b.textContent.includes('Harbor Bank') && !b.textContent.includes('Visa')).click()`);
    await popup.waitFor(`!!document.querySelector('.ring') && document.body.innerText.includes('Login credentials')`, 15000);
    await sleep(1200);
    await popup.shot("popup-item.png");
  });

  await step("4: save prompt after signing up", async () => {
    await site.ev(`location.reload()`);
    await site.waitFor(`!!document.getElementById('pass')`);
    await sleep(800);
    await site.ev(`(() => { const set = (id, v) => { const el = document.getElementById(id); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, v); el.dispatchEvent(new Event('input', {bubbles:true})); }; set('user', 'alex.morgan@example.com'); set('pass', 'Copper-new-2026!'); document.querySelector('button[type=submit]').click(); })()`);
    await site.waitFor(`!!document.querySelector('passauth-save')`, 8000);
    await sleep(400);
    await site.shot("page-save.png");
  });

  await step("5: generator and autofill settings", async () => {
    await popup.ev(`document.querySelector('[aria-label="Back"]').click()`);
    await popup.waitFor(`!!document.querySelector('.tabbar')`);
    await popup.click("Generator");
    await popup.waitFor(`!!document.querySelector('.gen-out')?.textContent`);
    await sleep(300);
    await popup.shot("popup-generator.png");
    await popup.click("Settings");
    await popup.ev(`[...document.querySelectorAll('.settings-row')].find(r => r.textContent.trim() === 'Autofill').click()`);
    await popup.waitFor(`document.body.innerText.includes('Default URI match detection')`);
    await sleep(300);
    await popup.shot("popup-autofill.png");
  });

  // ------------------------------------------------------------ compose
  const img = (f) => `data:image/png;base64,${readFileSync(join(RAW, f)).toString("base64")}`;
  const logo = `data:image/svg+xml;base64,${readFileSync(join(ROOT, "assets/passauth-logo.svg")).toString("base64")}`;
  const font = (w) => `file://${join(ROOT, `extension/node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-${w}-normal.woff2`)}`;
  const css = `
    @font-face { font-family: Plex; src: url(${font(400)}); font-weight: 400; }
    @font-face { font-family: Plex; src: url(${font(600)}); font-weight: 600; }
    * { box-sizing: border-box; margin: 0; }
    body { width: 1280px; height: 800px; overflow: hidden; background: #0b1a3a; color: #fff; font-family: Plex, system-ui, sans-serif; display: grid; grid-template-columns: 400px 1fr; }
    .copy { padding: 72px 0 0 64px; display: flex; flex-direction: column; gap: 22px; }
    .mark { display: flex; align-items: center; gap: 12px; font-weight: 600; font-size: 22px; }
    .mark img { height: 40px; }
    .mark b { color: #4aa3ff; font-weight: 600; }
    h1 { font-size: 40px; line-height: 1.12; font-weight: 600; letter-spacing: -0.01em; margin-top: 70px; }
    p { font-size: 19px; line-height: 1.5; color: #b3c0d6; max-width: 310px; }
    .stage { position: relative; }
    .browser { position: absolute; left: 30px; top: 92px; width: 800px; border-radius: 12px; overflow: hidden; background: #fff; box-shadow: 0 30px 70px rgb(0 0 0 / 0.45); }
    .bar { height: 44px; background: #e9edf3; display: flex; align-items: center; gap: 10px; padding: 0 14px; }
    .dots { display: flex; gap: 7px; } .dots i { width: 11px; height: 11px; border-radius: 50%; background: #c6ccd6; display: block; }
    .url { flex: 1; height: 28px; border-radius: 14px; background: #fff; color: #4a5568; font-size: 13px; display: flex; align-items: center; padding: 0 14px; }
    .ext { position: relative; width: 28px; height: 28px; display: grid; place-items: center; }
    .ext img { height: 20px; }
    .ext span { position: absolute; right: -3px; bottom: -2px; min-width: 16px; height: 16px; border-radius: 8px; background: #0866ED; color: #fff; font-size: 10px; font-weight: 600; display: grid; place-items: center; padding: 0 4px; }
    .browser > img { display: block; width: 800px; }
    .popup { position: absolute; border-radius: 12px; overflow: hidden; box-shadow: 0 24px 60px rgb(0 0 0 / 0.5); }
    .popup img { display: block; width: 100%; }
  `;
  const browser = (shot, badge = "1") => `
    <div class="browser">
      <div class="bar"><div class="dots"><i></i><i></i><i></i></div><div class="url">shop.copperleaf.example/sign-in</div>
      <div class="ext"><img src="${logo}">${badge ? `<span>${badge}</span>` : ""}</div></div>
      <img src="${img(shot)}">
    </div>`;
  const popupAt = (shot, left, top, width = 380) => `<div class="popup" style="left:${left}px;top:${top}px;width:${width}px"><img src="${img(shot)}"></div>`;
  const slide = (title, text, stage) =>
    `<!doctype html><html><head><meta charset="utf-8"><style>${css}</style></head><body><div class="copy"><div class="mark"><img src="${logo}"><span>Pass<b>Auth</b></span></div><h1>${title}</h1><p>${text}</p></div><div class="stage">${stage}</div></body></html>`;

  const slides = [
    ["01-vault", "Your logins, on every site", "See the logins saved for the site you're on and fill them in one click.", browser("page-shop.png") + popupAt("popup-vault.png", 430, 128, 360)],
    ["02-inline", "Fill from the login field", "Pick a login from the list under the field. The website can't read it.", browser("page-inline.png")],
    ["03-codes", "Verification codes built in", "Two-step codes count down next to the password and are copied after you fill.", popupAt("popup-item.png", 210, 52, 440)],
    ["04-save", "Save logins as you sign in", "PassAuth offers to save a new login or update a changed password.", browser("page-save.png", "")],
    ["05-control", "Your server, your keys", "Everything is encrypted on your device before it reaches the PassAuth server you run.", popupAt("popup-generator.png", 60, 90, 360) + popupAt("popup-autofill.png", 440, 90, 360)],
  ];
  const render = async (html, file, width, height) => {
    const htmlPath = join(RAW, `${file}.html`);
    writeFileSync(htmlPath, html);
    const t = await page(`file://${htmlPath}`);
    await t.look(width, height, 1);
    await t.ev(`document.fonts.ready.then(() => true)`);
    await sleep(400);
    await t.shot(`${file}.png`, { x: 0, y: 0, width, height });
    copyFileSync(join(RAW, `${file}.png`), join(OUT, file.startsWith("promo") ? `${file}.png` : `screenshots/${file}.png`));
    await cmd("Target.closeTarget", { targetId: t.targetId });
  };
  await step("compose 1280×800 screenshots", async () => {
    for (const [file, title, text, stage] of slides) await render(slide(title, text, stage), file, 1280, 800);
  });

  await step("promo tiles", async () => {
    const tile = (w, h, size, tag) => `<!doctype html><html><head><meta charset="utf-8"><style>${css}
      body { width: ${w}px; height: ${h}px; display: flex; align-items: center; justify-content: center; gap: ${size * 0.45}px; }
      img { height: ${size}px; } .t { font-weight: 600; font-size: ${size * 0.62}px; letter-spacing: -0.01em; } .t b { color: #4aa3ff; font-weight: 600; }
      .s { font-size: ${size * 0.24}px; color: #b3c0d6; margin-top: ${size * 0.08}px; }</style></head>
      <body><img src="${logo}"><div><div class="t">Pass<b>Auth</b></div>${tag ? `<div class="s">${tag}</div>` : ""}</div></body></html>`;
    await render(tile(440, 280, 70, "Your self-hosted password manager"), "promo-small-440x280", 440, 280);
    await render(tile(1400, 560, 150, "Passwords, codes and passkeys from your own server"), "promo-marquee-1400x560", 1400, 560);
    copyFileSync(join(ROOT, "extension/public/icons/icon-128.png"), join(OUT, "icon-128.png"));
  });
  console.log(`DONE → ${OUT}`);
} catch (e) {
  console.log(`\nFAILED: ${e.message}`);
} finally {
  ws.close();
  proc.kill();
}
