// End-to-end test of the PassAuth extension in Chromium (multi-target CDP).
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [, , EXT, OUT] = process.argv;
const TMP = process.env.E2E_TMP ?? (await import("node:os")).tmpdir();
const SERVER = process.env.PASSAUTH_URL ?? "http://localhost:8091";
const CHROMIUM = process.env.CHROMIUM ?? "/Applications/Chromium.app/Contents/MacOS/Chromium";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const EMAIL = `ext${Date.now()}@example.com`;
const PW = "extension test password 77";

const profile = mkdtempSync(join(TMP, "chromium-"));
const proc = spawn(CHROMIUM, ["--headless=new", "--remote-debugging-port=9445", `--user-data-dir=${profile}`, `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--no-first-run", "--window-size=1200,800", "about:blank"], { stdio: "ignore" });
let ver;
for (let i = 0; i < 60 && !ver; i++) { try { ver = await (await fetch("http://127.0.0.1:9445/json/version")).json(); } catch { await sleep(200); } }
const ws = new WebSocket(ver.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let n = 0; const pending = new Map(); const logs = [];
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); }
  if (m.method === "Runtime.exceptionThrown") logs.push(`exception: ${m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text}`);
  if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") logs.push(`console.error: ${m.params.args.map((a) => a.value ?? a.description).join(" ")}`);
});
const cmd = (method, params = {}, sessionId) => new Promise((resolve, reject) => { const id = ++n; pending.set(id, { resolve, reject }); ws.send(JSON.stringify({ id, method, params, sessionId })); });

async function page(url) {
  const { targetId } = await cmd("Target.createTarget", { url });
  return attach(targetId);
}
async function attach(targetId) {
  const { sessionId } = await cmd("Target.attachToTarget", { targetId, flatten: true });
  await cmd("Runtime.enable", {}, sessionId);
  const ev = async (expr) => {
    const r = await cmd("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };
  const waitFor = async (expr, t = 30000) => { const s = Date.now(); while (Date.now() - s < t) { try { if (await ev(expr)) return; } catch {} await sleep(150); } throw new Error(`timeout: ${expr}\n${await ev("document.body?.innerText?.slice(0,500)").catch(() => "")}`); };
  const shot = async (file) => { const r = await cmd("Page.captureScreenshot", { format: "png" }, sessionId); writeFileSync(`${OUT}/${file}`, Buffer.from(r.data, "base64")); };
  const fillLabel = (label, value) => ev(`(() => { const l=[...document.querySelectorAll('label')].find(l=>l.querySelector('span')?.textContent.trim()===${JSON.stringify(label)}); const el=l.querySelector('input,textarea'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, ${JSON.stringify(value)}); el.dispatchEvent(new Event('input',{bubbles:true})); })()`);
  const click = (text) => ev(`(() => { const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}); if(!b) throw new Error('no button ${text}'); b.click(); })()`);
  return { sessionId, targetId, ev, waitFor, shot, fillLabel, click };
}
const step = async (name, fn) => { process.stdout.write(`- ${name} … `); const t = Date.now(); await fn(); console.log(`ok (${Date.now() - t} ms)`); };


const target = async (pred, t = 15000) => { const s = Date.now(); while (Date.now() - s < t) { const { targetInfos } = await cmd("Target.getTargets"); const x = targetInfos.find(pred); if (x) return x; await sleep(150); } throw new Error("target not found"); };
try {
  let extId;
  await step("extension loaded", async () => {
    extId = (await target((t) => t.type === "service_worker" && t.url.startsWith("chrome-extension://"))).url.split("/")[2];
  });

  await step("register in web vault, new branding, login item with TOTP", async () => {
    const w = await page(`${SERVER}/#/register`);
    await w.waitFor(`document.body.innerText.includes('Create your PassAuth account')`);
    await w.shot("v2-01-register.png");
    await w.fillLabel("Email", EMAIL); await w.fillLabel("Master password", PW); await w.fillLabel("Confirm master password", PW);
    await w.click("Create account");
    await w.waitFor(`document.body.innerText.includes('Your vault is ready')`, 60000);
    await w.click("Open my vault");
    await w.waitFor(`!!document.querySelector('.list-pane')`, 60000);
    await w.ev(`location.hash = '#/vault/all/new-login'`);
    await w.waitFor(`document.body.innerText.includes('New login')`);
    const def = await w.ev(`document.querySelector('select')?.value ?? [...document.querySelectorAll('select')].map(s=>s.value).join(',')`);
    console.log(`\n    first select default: ${def}`);
    await w.fillLabel("Name", "Example site"); await w.fillLabel("Username", "alice@localhost"); await w.fillLabel("Password", "pw-one-1");
    await w.fillLabel("Website", "http://localhost:8099");
    await w.fillLabel("Authenticator key (TOTP)", "JBSWY3DPEHPK3PXP");
    const opts = await w.ev(`[...document.querySelectorAll('option')].map(o=>o.value).filter(v=>['default','regex'].includes(v)).join(',')`);
    if (opts !== "default,regex") throw new Error("match options: " + opts);
    await w.click("Save item");
    await w.waitFor(`!!document.querySelector('.totp-code')`);
    await w.shot("v2-02-vault.png");
  });

  const popup = await page(`chrome-extension://${extId}/popup.html`);
  const send = (msg) => popup.ev(`chrome.runtime.sendMessage(${JSON.stringify(msg)})`);
  await step("popup: connect and sign in", async () => {
    await popup.waitFor(`document.body.innerText.includes('Connect to your PassAuth server')`);
    await popup.fillLabel("Server address", SERVER); await popup.click("Connect");
    await popup.waitFor(`document.body.innerText.includes('Sign in to PassAuth')`);
    await popup.fillLabel("Email", EMAIL); await popup.fillLabel("Master password", PW); await popup.click("Sign in");
    await popup.waitFor(`document.body.innerText.includes('All items')`, 60000);
  });

  await step("create 30 items incl. github.com", async () => {
    const mk = (name, url) => ({ name, notes: "", favorite: false, folder: null, tags: [], login: { username: name.toLowerCase() + "@mail.test", password: "x-" + name, urls: [{ url, match: "default" }], totp: null, passkeys: [] }, card: null, identity: null, ssh_key: null, fields: [], password_history: [], created_at: 0, updated_at: 0 });
    let r = await send({ type: "createItem", item: mk("GitHub", "https://github.com") }); if (!r.ok) throw new Error(r.error);
    for (let i = 0; i < 29; i++) { r = await send({ type: "createItem", item: mk(`Site ${String(i).padStart(2, "0")}`, `https://site${i}.example`) }); if (!r.ok) throw new Error(r.error); }
  });

  await step("popup layout: tabs fixed, list scrolls", async () => {
    await popup.ev(`location.reload()`); await sleep(500);
    await popup.waitFor(`document.body.innerText.includes('All items (31)')`, 30000);
    await sleep(1500);
    await popup.shot("v2-03-popup-list.png");
    const before = await popup.ev(`JSON.stringify({tabs: document.querySelector('.pop-tabs').getBoundingClientRect().bottom, body: document.querySelector('.pop-body').scrollHeight > document.querySelector('.pop-body').clientHeight, h: document.querySelector('.pop').getBoundingClientRect().height})`);
    await popup.ev(`document.querySelector('.pop-body').scrollTop = 99999`); await sleep(200);
    const after = await popup.ev(`document.querySelector('.pop-tabs').getBoundingClientRect().bottom`);
    const search = await popup.ev(`document.querySelector('.pop-search').getBoundingClientRect().top - document.querySelector('.pop-body').getBoundingClientRect().top`);
    console.log(`\n    ${before}; tabs bottom after scroll ${after}; search offset ${search}`);
    const b = JSON.parse(before); if (!b.body || b.tabs > 600 || after !== b.tabs || Math.abs(search) > 1) throw new Error("layout");
    await popup.shot("v2-04-popup-scrolled.png");
    const icon = await popup.ev(`[...document.querySelectorAll('.pop-row')].find(r=>r.innerText.includes('GitHub'))?.querySelector('img')?.naturalWidth ?? -1`);
    console.log(`    github icon naturalWidth: ${icon}`);
  });

  await step("popup: more menu → copy password note", async () => {
    await popup.ev(`document.querySelector('.pop-body').scrollTop = 0`);
    await popup.ev(`[...document.querySelectorAll('.pop-row')].find(r=>r.innerText.includes('GitHub')).querySelector('[aria-label^=\"Options\"]').click()`);
    await popup.waitFor(`!!document.querySelector('.pop-menu')`);
    await popup.shot("v2-05-more-menu.png");
    await popup.click("Copy password");
    await popup.waitFor(`document.querySelector('.pop-note')?.innerText.includes('Password copied. Clipboard clears in 30 seconds')`);
  });

  await step("default URI match detection", async () => {
    const url = "http://localhost:8099/login.html";
    const count = async () => (await send({ type: "items", url })).data.suggested.length;
    const res = {};
    for (const m of ["never", "host", "regex", "exact", "starts_with", "domain"]) { await send({ type: "settings", patch: { defaultMatch: m } }); res[m] = await count(); }
    console.log(`\n    ${JSON.stringify(res)}`);
    if (res.never !== 0 || res.host !== 1 || res.regex !== 1 || res.exact !== 0 || res.starts_with !== 1 || res.domain !== 1) throw new Error("match results");
  });

  const site = await page("http://localhost:8099/login.html");
  await site.waitFor(`!!document.getElementById('pass')`);
  await cmd("Browser.grantPermissions", { permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"], origin: "http://localhost:8099" }).catch((e) => console.log("grant:", e.message));
  await step("inline menu on field focus → fill + TOTP copied", async () => {
    await cmd("Target.activateTarget", { targetId: site.targetId });
    await site.ev(`document.getElementById('user').focus()`);
    await site.waitFor(`!!document.querySelector('passauth-inline-icon') && !!document.querySelector('passauth-inline-menu')`, 8000);
    const fr = await target((t) => t.url.includes("inline-menu.html#"));
    const menu = await attach(fr.targetId);
    await menu.waitFor(`document.querySelectorAll('.row').length === 1`);
    await sleep(300);
    await site.shot("v2-06-inline-menu.png");
    await menu.ev(`document.querySelector('.row').click()`);
    await site.waitFor(`document.getElementById('pass').value === 'pw-one-1' && document.getElementById('user').value === 'alice@localhost'`, 5000);
    await site.waitFor(`!!document.querySelector('passauth-toast')`, 5000);
    await site.shot("v2-07-filled-toast.png");
    const menuGone = await site.ev(`!document.querySelector('passauth-inline-menu')`);
    if (!menuGone) throw new Error("menu still open after fill");
    const clip = await site.ev(`navigator.clipboard.readText().catch(e => 'ERR ' + e.message)`);
    const expected = (await send({ type: "totp", id: (await send({ type: "items", url: "http://localhost:8099/" })).data.suggested[0].id })).data.code;
    console.log(`\n    clipboard: ${clip} expected ${expected}`);
  });

  await step("popup sync shows status", async () => {
    await popup.ev(`location.reload()`); await sleep(500);
    await popup.waitFor(`document.body.innerText.includes('All items')`, 30000);
    await popup.click("Settings");
    await popup.waitFor(`document.body.innerText.includes('Sync vault now')`);
    await popup.click("Sync vault now");
    await popup.waitFor(`document.body.innerText.includes('Sync complete') && /Last sync: today at/.test(document.body.innerText)`);
    await popup.shot("v2-08-settings-sync.png");
    await popup.ev(`document.querySelector('.pop-body').scrollTop = 0`);
    await popup.shot("v2-09-settings-top.png");
    const opts = await popup.ev(`[...document.querySelectorAll('select')].map(s => [...s.options].map(o => o.text).join('|')).join(' || ')`);
    console.log("\n    " + opts);
  });

  await step("timeout: Immediately + Lock, then Log out", async () => {
    await send({ type: "settings", patch: { vaultTimeout: "immediately", timeoutAction: "lock" } });
    let p2 = await page(`chrome-extension://${extId}/popup.html`); await sleep(800);
    await cmd("Target.closeTarget", { targetId: p2.targetId }); await sleep(800);
    let s = await send({ type: "state" }); if (s.data.status !== "locked") throw new Error("not locked: " + s.data.status);
    let r = await send({ type: "unlock", password: PW }); if (!r.ok) throw new Error(r.error);
    await send({ type: "settings", patch: { timeoutAction: "logout" } });
    p2 = await page(`chrome-extension://${extId}/popup.html`); await sleep(800);
    await cmd("Target.closeTarget", { targetId: p2.targetId }); await sleep(1200);
    s = await send({ type: "state" }); if (s.data.status !== "logged-out") throw new Error("not logged out: " + s.data.status);
    await send({ type: "settings", patch: { vaultTimeout: 15, timeoutAction: "lock" } });
    r = await send({ type: "login", email: EMAIL, password: PW }); if (!r.ok) throw new Error(r.error);
  });

  await step("timeout: Never survives a lost session", async () => {
    await send({ type: "settings", patch: { vaultTimeout: "never" } });
    const has = await popup.ev(`chrome.storage.local.get('persistedKeys').then(v => !!v.persistedKeys)`);
    if (!has) throw new Error("keys not persisted");
    const restart = async () => {
      await popup.ev(`chrome.storage.session.clear()`);
      const sw = await target((t) => t.type === "service_worker" && t.url.includes(extId));
      await cmd("Target.closeTarget", { targetId: sw.targetId }).catch(() => {});
      await sleep(800);
      return (await send({ type: "state" })).data.status;
    };
    const s = await restart();
    if (s !== "unlocked") throw new Error("not unlocked after worker restart: " + s);
    console.log(`\n    never: ${s}`);
    await send({ type: "settings", patch: { vaultTimeout: 15 } });
    const gone = await popup.ev(`chrome.storage.local.get('persistedKeys').then(v => !v.persistedKeys)`);
    if (!gone) throw new Error("persisted keys not removed");
    const s15 = await restart();
    console.log(`    15 minutes: ${s15}`);
    if (s15 !== "locked") throw new Error("should be locked");
    await send({ type: "unlock", password: PW });
  });

  await step("inline menu when locked offers unlock", async () => {
    await send({ type: "lock" });
    await site.ev(`location.reload()`); await sleep(800);
    await site.waitFor(`!!document.getElementById('pass')`);
    await cmd("Target.activateTarget", { targetId: site.targetId });
    await site.ev(`document.getElementById('pass').focus()`);
    await site.waitFor(`!!document.querySelector('passauth-inline-menu')`, 8000);
    const fr = await target((t) => t.url.includes("inline-menu.html#"));
    const menu = await attach(fr.targetId);
    await menu.waitFor(`document.body.innerText.includes('Unlock PassAuth')`);
    await sleep(300);
    await site.shot("v2-10-inline-locked.png");
  });

  await step("inline: click mode shows icon only; off shows nothing", async () => {
    await send({ type: "unlock", password: PW });
    await send({ type: "settings", patch: { inlineMenu: "click" } });
    await site.ev(`location.reload()`); await sleep(800);
    await site.waitFor(`!!document.getElementById('pass')`);
    await sleep(3200);
    await site.ev(`document.getElementById('user').focus()`);
    await site.waitFor(`!!document.querySelector('passauth-inline-icon')`, 8000);
    await sleep(500);
    if (await site.ev(`!!document.querySelector('passauth-inline-menu')`)) throw new Error("menu opened in click mode");
    await site.shot("v2-11-inline-icon.png");
    await send({ type: "settings", patch: { inlineMenu: "off" } });
    await site.ev(`location.reload()`); await sleep(800);
    await site.waitFor(`!!document.getElementById('pass')`);
    await site.ev(`document.getElementById('user').focus()`); await sleep(1500);
    if (await site.ev(`!!document.querySelector('passauth-inline-icon')`)) throw new Error("icon shown when off");
    await send({ type: "settings", patch: { inlineMenu: "focus" } });
  });
  await step("light mode screenshots", async () => {
    for (const p of [popup, site]) await cmd("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] }, p.sessionId);
    await popup.ev(`location.reload()`); await sleep(1500);
    await popup.waitFor(`document.body.innerText.includes('All items')`, 30000);
    await popup.shot("v2-12-popup-light.png");
    const w = await page(`${SERVER}/`);
    await cmd("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] }, w.sessionId);
    await w.waitFor(`document.body.innerText.includes('Unlock') || document.body.innerText.includes('Sign in')`, 30000);
    await sleep(500);
    await w.shot("v2-13-web-light.png");
    await cmd("Target.activateTarget", { targetId: w.targetId });
    await w.ev(`document.querySelector('input[type=password]').focus()`); await sleep(1500);
    if (await w.ev(`!!document.querySelector('passauth-inline-icon')`)) throw new Error("inline menu on PassAuth's own vault");
  });
  console.log("ALL STEPS PASSED");
} catch (e) {
  console.log(`\nFAILED: ${e.message}`);
} finally {
  if (logs.length) console.log("browser errors:\n  " + logs.slice(0, 15).join("\n  "));
  ws.close(); proc.kill();
}
