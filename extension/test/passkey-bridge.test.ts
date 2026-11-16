// @vitest-environment happy-dom
// @vitest-environment-options {"url": "https://login.example.com/passkey"}
// The page bridge (content/passkey-bridge.ts) cancels the requests it has open when the page goes away (reload,
// navigation, closing), so their confirmation windows close. Found in a real browser: after a reload the old window
// stayed open behind the browser window and the tab refused new requests until it timed out.

import { expect, test, vi } from "vitest";
import { installPasskeyBridge } from "../src/content/passkey-bridge";

test("pagehide cancels the requests still waiting for PassAuth, and only those", async () => {
  Object.defineProperty(globalThis, "origin", { value: location.origin, configurable: true, writable: true });
  const sent: unknown[] = [];
  const answers = new Map<string, (r: unknown) => void>();
  vi.spyOn(chrome.runtime, "sendMessage").mockImplementation(((msg: { type: string; bridgeId: string }) => {
    sent.push(msg);
    // passkey:get waits for the user (its window is open); cancel is answered at once.
    return msg.type === "passkey:get" ? new Promise((resolve) => answers.set(msg.bridgeId, resolve)) : Promise.resolve(undefined);
  }) as unknown as typeof chrome.runtime.sendMessage);
  installPasskeyBridge();

  const ask = (id: string) => window.dispatchEvent(new MessageEvent("message", { source: window, data: { source: "passauth-page", id, kind: "get", options: { challenge: "AAAA" } } }));
  ask("r1");
  ask("r2");
  await new Promise((r) => setTimeout(r, 0));
  expect(sent.map((m) => (m as { type: string }).type)).toStrictEqual(["passkey:get", "passkey:get"]);

  // r2 is answered (the user signed in): only r1 is still open when the page goes away.
  answers.get("r2")?.({ error: { name: "NotAllowedError", message: "x" } });
  await new Promise((r) => setTimeout(r, 0));
  window.dispatchEvent(new Event("pagehide"));
  // Marked as the page going away (not the page aborting its request, which holds the tab back).
  expect(sent.slice(2)).toStrictEqual([{ type: "passkey:cancel", bridgeId: "r1", gone: true }]);
  // Nothing twice.
  window.dispatchEvent(new Event("pagehide"));
  expect(sent).toHaveLength(3);
});

test("L-3: a sign-in request says whether the page had a recent click or key press (read here, not from the page)", async () => {
  Object.defineProperty(globalThis, "origin", { value: location.origin, configurable: true, writable: true });
  const sent: { type: string; activated?: boolean }[] = [];
  vi.spyOn(chrome.runtime, "sendMessage").mockImplementation(((msg: { type: string; activated?: boolean }) => {
    sent.push(msg);
    return Promise.resolve({ fallback: true });
  }) as unknown as typeof chrome.runtime.sendMessage);
  installPasskeyBridge();
  const ask = (id: string, extra: Record<string, unknown> = {}) =>
    window.dispatchEvent(new MessageEvent("message", { source: window, data: { source: "passauth-page", id, kind: "get", options: { challenge: "AAAA" }, ...extra } }));
  for (const isActive of [false, true]) {
    Object.defineProperty(navigator, "userActivation", { value: { isActive }, configurable: true });
    // Whatever the page claims in its message, the bridge reads the activation itself.
    ask(`a-${isActive}`, { activated: !isActive });
    await new Promise((r) => setTimeout(r, 0));
  }
  expect(sent.filter((m) => m.type === "passkey:get").map((m) => m.activated)).toStrictEqual([false, true]);
});
