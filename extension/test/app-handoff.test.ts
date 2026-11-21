// Safari: the sign-in form starts with the server, email and Secret Key another PassAuth app on the device left for it
// (shared/app-handoff.ts, answered by safari/Extension/Handoff.swift). Other browsers never ask.

import { afterEach, expect, test } from "vitest";
import { appHandoff } from "../src/shared/app-handoff";

const rt = globalThis.chrome.runtime as unknown as { getURL: (p: string) => string; sendNativeMessage?: unknown };
const realGetURL = rt.getURL;
let asked: unknown[] = [];
function safari(reply: unknown) {
  rt.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  rt.sendNativeMessage = async (app: string, message: unknown) => {
    asked.push([app, message]);
    if (reply instanceof Error) throw reply;
    return reply;
  };
}
afterEach(() => {
  rt.getURL = realGetURL;
  delete rt.sendNativeMessage;
  asked = [];
});

test("Safari: server, email and Secret Key from the app", async () => {
  safari({ server: "https://vault.example.com", email: "alex@example.com", secretKey: "A3-KEY" });
  expect(await appHandoff()).toEqual({ server: "https://vault.example.com", email: "alex@example.com", secretKey: "A3-KEY" });
  expect(asked).toEqual([["io.passauth.safari", { type: "handoff" }]]);
});

test("Safari: no hand-off, a broken answer or a failed call → nothing", async () => {
  for (const reply of [{ none: true }, { server: "javascript:alert(1)", email: "a@b.c" }, { server: "https://s" }, null, "x", new Error("no app")]) {
    safari(reply);
    expect(await appHandoff()).toBeNull();
  }
});

test("Safari: only these three fields are taken", async () => {
  safari({ server: "https://s.example", email: "e@x.y", tokens: { refresh: "r" }, secretKey: "" });
  expect(await appHandoff()).toEqual({ server: "https://s.example", email: "e@x.y" });
});

test("other browsers: never asks", async () => {
  rt.sendNativeMessage = async () => {
    throw new Error("must not be called");
  };
  expect(await appHandoff()).toBeNull();
});

test("sameServer: the same server despite case, a default port or a trailing slash; another host or path is not", async () => {
  const { sameServer } = await import("../src/shared/app-handoff");
  expect(sameServer("https://Vault.Example.com/", "https://vault.example.com")).toBe(true);
  expect(sameServer("https://vault.example.com:443", "https://vault.example.com")).toBe(true);
  expect(sameServer("https://vault.example.com/pa/", "https://vault.example.com/pa")).toBe(true);
  expect(sameServer("https://vault.example.com", "https://other.example.com")).toBe(false);
  expect(sameServer("https://vault.example.com/a", "https://vault.example.com/b")).toBe(false);
  expect(sameServer("not a url", "https://vault.example.com")).toBe(false);
});
