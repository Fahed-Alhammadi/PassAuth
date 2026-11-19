/** The key page renders signed out, without the vault, and offers the key only for a complete link of a waiting sign-in. */
import { renderToString } from "react-dom/server";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  const none = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  Object.assign(globalThis, { location: new URL("https://vault.example.com/two-step/key"), localStorage: none, sessionStorage: none, history: { replaceState: () => {} } });
});

import { routes } from "../App";
import { CONTEXT_ENDED, CONTEXT_WARNING, bytesToB64url, jsonToB64url, parseKeyPageFragment, type KeyPageContext } from "../lib/key-page";
import { KeyPageView, TwoStepKeyDonePage, TwoStepKeyPage, type Step } from "./TwoStepKey";

const STATE = bytesToB64url(new Uint8Array(16).fill(4));
const OPTIONS = {
  publicKey: { challenge: bytesToB64url(new Uint8Array(32).fill(3)), rpId: "vault.example.com", allowCredentials: [{ type: "public-key", id: "AAEC" }] },
};
const HASH = `v=1&options=${jsonToB64url(OPTIONS)}&return=app&state=${STATE}`;
const REQUEST = parseKeyPageFragment(`#${HASH}`, "vault.example.com")!;
const CONTEXT: KeyPageContext = { client: "android", deviceName: null, ip: "203.0.113.5", startedAt: 1000 };

function withHash(hash: string) {
  (globalThis.location as unknown as URL).hash = hash;
}
afterEach(() => withHash(""));

const view = (step: Step, context: KeyPageContext | null = CONTEXT, request = REQUEST, error: string | null = null) =>
  renderToString(<KeyPageView request={request} step={step} context={context} error={error} now={1030} onUse={() => {}} onCancel={() => {}} />);

describe("key page", () => {
  it("while the sign-in is being checked: no button yet", () => {
    withHash(HASH);
    const html = renderToString(<TwoStepKeyPage />);
    expect(html).toContain("Checking this sign-in…");
    expect(html).not.toContain("<button");
  });
  it("a waiting sign-in: the context line, the warning, then the key; nothing about the account", () => {
    const html = view("ready");
    expect(html).toContain("Signing in on PassAuth for Android from 203.0.113.5, 30 seconds ago.");
    expect(html).toContain(CONTEXT_WARNING.replace("'", "&#x27;"));
    expect(html).toContain("Use your security key to finish signing in to PassAuth.");
    expect(html).toContain("Use security key");
    expect(html).toContain("Cancel");
    expect(html).not.toMatch(/@/);
  });
  it("device names are shown as text, never markup", () => {
    const html = view("ready", { ...CONTEXT, deviceName: "<img src=x onerror=alert(1)>" });
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });
  it("an ended or unknown sign-in: the message, no button", () => {
    const html = view("ended", null);
    expect(html).toContain(CONTEXT_ENDED.replace("'", "&#x27;"));
    expect(html).not.toContain("<button");
  });
  it("after a failure: the error and Try again; after handing over: go back", () => {
    expect(view("failed", CONTEXT, REQUEST, "The security key wasn't used.")).toContain("Try again");
    const handed = view("handed");
    expect(handed).toContain("Go back to PassAuth to finish signing in.");
    expect(handed).not.toContain("<button");
  });
  it("an incomplete link says so, with no button", () => {
    for (const hash of [
      "",
      `v=1&options=${jsonToB64url(OPTIONS)}&return=https://evil.example/&state=${STATE}`,
      `v=1&options=${jsonToB64url(OPTIONS)}&return=app`,
      `v=1&options=${jsonToB64url({ publicKey: { ...OPTIONS.publicKey, rpId: "evil.example" } })}&return=app&state=${STATE}`,
      "v=1&return=app",
    ]) {
      withHash(hash);
      const html = renderToString(<TwoStepKeyPage />);
      expect(html).toContain("This link isn&#x27;t complete");
      expect(html).toContain("Go back to the app and try again.");
      expect(html).not.toContain("<button");
    }
  });
  it("adds no marker other pages could imitate", () => {
    withHash(HASH);
    expect(renderToString(<TwoStepKeyPage />)).not.toContain("passauth-key-page");
  });
  it("the done page tells the user to close the window", () => {
    expect(renderToString(<TwoStepKeyDonePage />)).toContain("You can close this window.");
  });
  it("both are public routes, outside the signed-in shell", () => {
    withHash(HASH);
    for (const [path, text] of [
      ["/two-step/key", "Checking this sign-in…"],
      ["/two-step/key/done", "You can close this window."],
    ]) {
      const html = renderToString(<RouterProvider router={createMemoryRouter(routes, { initialEntries: [path] })} />);
      expect(html).toContain(text);
      expect(html).not.toContain("Master password");
    }
  });
});
