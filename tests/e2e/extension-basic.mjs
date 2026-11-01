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
const proc = spawn(CHROMIUM, ["--headless=new", "--remote-debugging-port=9444", `--user-data-dir=${profile}`, `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--no-first-run", "--window-size=1200,800", "about:blank"], { stdio: "ignore" });
let ver;
for (let i = 0; i < 60 && !ver; i++) { try { ver = await (await fetch("http://127.0.0.1:9444/json/version")).json(); } catch { await sleep(200); } }
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

  await step("register user and save a login for the test site (web vault)", async () => {
    const w = await page(`${SERVER}/#/register`);
    await w.waitFor(`document.body.innerText.includes('Create your PassAuth account')`);
    await w.fillLabel("Email", EMAIL); await w.fillLabel("Master password", PW); await w.fillLabel("Confirm master password", PW);
    await w.click("Create account");
    await w.waitFor(`document.body.innerText.includes('Your vault is ready')`, 60000);
    await w.click("Open my vault");
    await w.waitFor(`!!document.querySelector('.list-pane')`, 60000);
    await w.ev(`location.hash = '#/vault/all/new-login'`);
    await w.waitFor(`document.body.innerText.includes('New login')`);
    await w.fillLabel("Name", "Example site"); await w.fillLabel("Username", "alice@localhost"); await w.fillLabel("Password", "old-password-1");
    await w.fillLabel("Website", "http://localhost:8099");
    await w.fillLabel("Authenticator key (TOTP)", "JBSWY3DPEHPK3PXP");
    await w.click("Save item");
    await w.waitFor(`!!document.querySelector('.totp-code')`);
  });

  const popup = await page(`chrome-extension://${extId}/popup.html`);
  const send = (msg) => popup.ev(`chrome.runtime.sendMessage(${JSON.stringify(msg)})`);
  await step("popup: connect server and sign in", async () => {
    await popup.waitFor(`document.body.innerText.includes('Connect to your PassAuth server')`);
    await popup.shot("ext-01-setup.png");
    await popup.fillLabel("Server address", SERVER);
    await popup.click("Connect");
    await popup.waitFor(`document.body.innerText.includes('Sign in to PassAuth')`);
    await popup.fillLabel("Email", EMAIL); await popup.fillLabel("Master password", PW);
    await popup.click("Sign in");
    await popup.waitFor(`document.body.innerText.includes('All items')`, 60000);
  });

  const site = await page("http://localhost:8099/login.html");
  await site.waitFor(`!!document.getElementById('pass')`);
  await step("popup shows suggestion for the site and fills it", async () => {
    await cmd("Target.activateTarget", { targetId: site.targetId });
    const tabId = await popup.ev(`chrome.tabs.query({url:'http://localhost:8099/*'}).then(t=>t[0].id)`);
    const items = await send({ type: "items", url: "http://localhost:8099/login.html" });
    if (!items.ok || items.data.suggested.length !== 1) throw new Error(`suggestions: ${JSON.stringify(items)}`);
    const r = await send({ type: "fill", id: items.data.suggested[0].id, tabId });
    if (!r.ok) throw new Error(r.error);
    await site.waitFor(`document.getElementById('pass').value === 'old-password-1'`, 5000);
    const user = await site.ev(`document.getElementById('user').value`);
    if (user !== "alice@localhost") throw new Error(`username filled as ${user}`);
    const totp = await send({ type: "totp", id: items.data.suggested[0].id });
    if (!/^\d{6}$/.test(totp.data.code)) throw new Error("totp");
  });

  await step("refuses to fill on a different site", async () => {
    const other = await page("http://127.0.0.1:8099/login.html");
    await other.waitFor(`!!document.getElementById('pass')`);
    const tabId = await popup.ev(`chrome.tabs.query({url:'http://127.0.0.1:8099/*'}).then(t=>t[0].id)`);
    const items = await send({ type: "items" });
    const r = await send({ type: "fill", id: items.data.all.find((i) => i.name === "Example site").id, tabId });
    if (r.ok) throw new Error("filled on the wrong site!");
    console.log(`\n    refused: "${r.error}"`);
    const v = await other.ev(`document.getElementById('pass').value`);
    if (v) throw new Error("password leaked into the other page");
  });

  await step("save prompt after changing the password", async () => {
    await site.ev(`(() => { const p=document.getElementById('pass'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(p,'new-password-2'); p.dispatchEvent(new Event('input',{bubbles:true})); document.querySelector('button').click(); })()`);
    await site.waitFor(`!!document.querySelector('passauth-save')`, 5000);
    await site.shot("ext-02-save-banner.png");
    const { root } = await cmd("DOM.getDocument", { depth: -1, pierce: true }, site.sessionId);
    const { nodeId } = await cmd("DOM.querySelector", { nodeId: root.nodeId, selector: "passauth-save" }, site.sessionId);
    const { node } = await cmd("DOM.describeNode", { nodeId, depth: -1, pierce: true }, site.sessionId);
    const find = (nd) => nd.attributes?.includes("data-a") && nd.attributes[nd.attributes.indexOf("data-a") + 1] === "save" ? nd : [...(nd.children ?? []), ...(nd.shadowRoots ?? [])].map(find).find(Boolean);
    const btn = find(node);
    const { model } = await cmd("DOM.getBoxModel", { backendNodeId: btn.backendNodeId }, site.sessionId);
    const [x1, y1, , , x3, y3] = model.content;
    for (const type of ["mousePressed", "mouseReleased"]) await cmd("Input.dispatchMouseEvent", { type, x: (x1 + x3) / 2, y: (y1 + y3) / 2, button: "left", clickCount: 1 }, site.sessionId);
    for (let i = 0; i < 40; i++) {
      await sleep(250);
      const items = await send({ type: "items" });
      const id = items.data.all.find((i) => i.name === "Example site").id;
      const it = await send({ type: "item", id });
      if (it.data.item.login.password === "new-password-2") return;
    }
    throw new Error("password was not updated");
  });

  await step("passkey: register on localhost", async () => {
    const pk = await page("http://localhost:8099/passkey.html");
    await pk.waitFor(`typeof register === 'function'`);
    const result = pk.ev(`register()`);
    let confirmWin;
    for (let i = 0; i < 60 && !confirmWin; i++) {
      const { targetInfos } = await cmd("Target.getTargets");
      const t = targetInfos.find((t) => t.url.includes("popup.html#passkey="));
      if (t) confirmWin = await attach(t.targetId); else await sleep(200);
    }
    if (!confirmWin) throw new Error("confirmation window did not open");
    await confirmWin.waitFor(`document.body.innerText.includes('Save passkey')`);
    await confirmWin.shot("ext-03-passkey-confirm.png");
    await confirmWin.click("Save passkey");
    const r = await result;
    console.log(`\n    created: ${JSON.stringify(r)}`);
    if (!r.isPKC || r.alg !== -7 || !r.hasKey) throw new Error("bad credential");

    const login = pk.ev(`login()`);
    let win2;
    for (let i = 0; i < 60 && !win2; i++) {
      const { targetInfos } = await cmd("Target.getTargets");
      const t = targetInfos.find((t) => t.url.includes("popup.html#passkey="));
      if (t) win2 = await attach(t.targetId); else await sleep(200);
    }
    await win2.waitFor(`document.body.innerText.includes('Sign in with a passkey')`);
    await win2.click("Sign in");
    const a = await login;
    console.log(`    assertion: ${JSON.stringify(a)}`);
    if (!a.sameId || a.type !== "webauthn.get" || !a.challengeOk || a.user !== "user-123" || a.origin !== "http://localhost:8099") throw new Error("bad assertion");
  });

  await step("lock clears keys; locked popup asks for password", async () => {
    await send({ type: "lock" });
    const s = await send({ type: "state" });
    if (s.data.status !== "locked") throw new Error(JSON.stringify(s));
    const items = await send({ type: "items" });
    if (items.ok) throw new Error("items readable while locked");
  });
  console.log("ALL EXTENSION STEPS PASSED");
} catch (e) {
  console.log(`\nFAILED: ${e.message}`);
} finally {
  if (logs.length) console.log("browser errors:\n  " + logs.slice(0, 15).join("\n  "));
  ws.close(); proc.kill();
}
