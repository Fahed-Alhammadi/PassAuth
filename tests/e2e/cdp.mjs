// Minimal Chrome DevTools Protocol driver (no dependencies; Node 26 global WebSocket).
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CHROME = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function launch({ port = 9333, width = 1280, height = 820, extraArgs = [] } = {}) {
  const profile = mkdtempSync(join(process.env.E2E_TMP ?? tmpdir(), "chrome-"));
  const proc = spawn(CHROME, [
    "--headless=new", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
    `--window-size=${width},${height}`, "--no-first-run", "--no-default-browser-check", "--disable-gpu", ...extraArgs, "about:blank",
  ], { stdio: "ignore" });
  let targets;
  for (let i = 0; i < 50; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); if (targets.length) break; } catch {}
    await sleep(200);
  }
  const page = targets.find((t) => t.type === "page");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r, { once: true }));
  let id = 0;
  const pending = new Map();
  const logs = [];
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); }
    if (m.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(m.params.type)) logs.push(`${m.params.type}: ${m.params.args.map((a) => a.value ?? a.description).join(" ")}`);
    if (m.method === "Runtime.exceptionThrown") logs.push(`exception: ${m.params.exceptionDetails.exception?.description ?? m.params.exceptionDetails.text}`);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => { const i = ++id; pending.set(i, { resolve, reject }); ws.send(JSON.stringify({ id: i, method, params })); });
  await send("Page.enable"); await send("Runtime.enable"); await send("DOM.enable");
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });

  const evaluate = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };
  const helpers = `
    window.__q = (sel, text) => [...document.querySelectorAll(sel)].find(e => !text || e.textContent.trim().includes(text));
    window.__fillLabel = (label, value) => {
      const l = [...document.querySelectorAll('label')].find(l => l.querySelector('span')?.textContent.trim() === label);
      const el = l?.querySelector('input,textarea,select'); if (!el) throw new Error('no field ' + label);
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
      el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
    };`;
  const api = {
    send, evaluate, logs,
    async goto(url) { await send("Page.navigate", { url }); await sleep(600); await evaluate(helpers); },
    async ensureHelpers() { await evaluate(helpers); },
    async waitFor(expr, timeout = 15000) {
      const t = Date.now();
      while (Date.now() - t < timeout) { try { await evaluate(helpers); if (await evaluate(expr)) return; } catch {} await sleep(150); }
      throw new Error(`timeout waiting for: ${expr}\n${(await evaluate("document.body.innerText").catch(() => "")).slice(0, 600)}`);
    },
    waitText: (text, timeout) => api.waitFor(`document.body.innerText.includes(${JSON.stringify(text)})`, timeout),
    fill: (label, value) => evaluate(`__fillLabel(${JSON.stringify(label)}, ${JSON.stringify(value)})`),
    click: (sel, text) => evaluate(`(() => { const e = __q(${JSON.stringify(sel)}, ${JSON.stringify(text ?? "")}); if (!e) throw new Error('no element ${sel} ${text ?? ""}'); e.click(); })()`),
    async screenshot(path) { const r = await send("Page.captureScreenshot", { format: "png" }); writeFileSync(path, Buffer.from(r.data, "base64")); },
    async setFile(selector, path) {
      const { root } = await send("DOM.getDocument", { depth: -1, pierce: true });
      const { nodeId } = await send("DOM.querySelector", { nodeId: root.nodeId, selector });
      await send("DOM.setFileInputFiles", { nodeId, files: [path] });
    },
    async close() { ws.close(); proc.kill(); },
  };
  return api;
}
export { sleep };
