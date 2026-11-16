// @vitest-environment happy-dom
// @vitest-environment-options {"url": "https://shop.example/account"}
// Field detection (content/fields.ts, C13): login, new-password, one-time-code, card and identity fields; hint text
// from <label>, aria-labelledby and title; closed shadow roots through chrome.dom; one scan per event.

import { describe, expect, test, vi } from "vitest";
import { fieldKind, hasFields, loginPasswordField, otpBoxes, otpField, passwordRole, Scan, usernameFieldFor } from "../src/content/fields";
import { fakeLayout, page } from "./dom";

fakeLayout();

const kinds = (ids: Record<string, HTMLInputElement>) => {
  const scan = new Scan();
  return Object.fromEntries(Object.entries(ids).map(([id, el]) => [id, fieldKind(el, scan)]));
};

describe("login and sign-up forms", () => {
  test("a sign-in form: user name and current password are login fields", () => {
    const f = page(`<form><input id="user" name="login"><input id="pw" type="password"><button>Go</button></form>`, "user", "pw");
    expect(kinds(f)).toStrictEqual({ user: "login", pw: "login" });
    const scan = new Scan();
    expect(usernameFieldFor(f.pw, scan)).toBe(f.user);
    expect(loginPasswordField(scan)).toBe(f.pw);
  });

  test("a sign-up form: the new password and its confirmation are new-password fields, never filled from a saved login", () => {
    const f = page(
      `<form><input id="email" type="email" autocomplete="email"><input id="pw" type="password" autocomplete="new-password"><input id="again" type="password" name="password_confirm"></form>`,
      "email",
      "pw",
      "again",
    );
    expect(kinds(f)).toStrictEqual({ email: "login", pw: "new-password", again: "new-password" });
    expect(loginPasswordField(new Scan())).toBe(null);
  });

  test("a change-password form without hints: the first of three is the current one", () => {
    const f = page(`<form><input id="a" type="password"><input id="b" type="password"><input id="c" type="password"></form>`, "a", "b", "c");
    const scan = new Scan();
    expect([f.a, f.b, f.c].map((p) => passwordRole(p, scan))).toStrictEqual(["current", "new", "new"]);
    expect(loginPasswordField(scan)).toBe(f.a);
  });

  test("current-password beats a field before it; the label decides without autocomplete", () => {
    const f = page(`<form><label for="n">Choose a password</label><input id="n" type="password"><input id="c" type="password" autocomplete="current-password"></form>`, "n", "c");
    const scan = new Scan();
    expect(passwordRole(f.n, scan)).toBe("new");
    expect(loginPasswordField(scan)).toBe(f.c);
  });

  test("a password shown as text (show-password button) still counts when it says so", () => {
    const f = page(`<form><input id="u" name="user"><input id="pw" type="text" name="password" autocomplete="current-password"></form>`, "u", "pw");
    expect(kinds(f)).toStrictEqual({ u: "login", pw: "login" });
    // A user name field that only abuses autocomplete="new-password" is not a password field.
    const g = page(`<form><input id="u" name="username" autocomplete="new-password"><input id="pw" type="password"></form>`, "u", "pw");
    expect(kinds(g)).toStrictEqual({ u: "login", pw: "login" });
  });

  test("hint text comes from <label>, aria-labelledby and title, not only name and id", () => {
    const f = page(
      `<label for="a">Email address</label><input id="a">
       <span id="lb">Your account</span><input id="b" aria-labelledby="lb">
       <input id="c" title="User ID">
       <input id="d" placeholder="Comment">`,
      "a",
      "b",
      "c",
      "d",
    );
    expect(kinds(f)).toStrictEqual({ a: "login", b: "login", c: "login", d: null });
  });

  test("search boxes and hidden or disabled fields are never login fields", () => {
    const f = page(
      `<input id="s" name="q" aria-label="Search the site"><input id="h" type="password" style="display:none"><input id="d" type="password" disabled><input id="r" type="password" readonly>`,
      "s",
      "h",
      "d",
      "r",
    );
    expect(kinds(f)).toStrictEqual({ s: null, h: null, d: null, r: null });
  });
});

describe("one-time codes", () => {
  test("autocomplete one-time-code and the usual wording", () => {
    const f = page(`<input id="a" autocomplete="one-time-code"><input id="b" name="otp_code"><label>Verification code <input id="c" type="tel"></label>`, "a", "b", "c");
    expect(kinds(f)).toStrictEqual({ a: "otp", b: "otp", c: "otp" });
    expect(otpField(new Scan())).toBe(f.a);
  });

  test("six single-character boxes are one code: filling starts at the first box whichever one has the focus", () => {
    const boxes = Array.from({ length: 6 }, (_, i) => `<input id="b${i}" maxlength="1" inputmode="numeric">`).join("");
    const f = page(`<form>${boxes}</form>`, "b0", "b3");
    const scan = new Scan();
    expect(fieldKind(f.b3, scan)).toBe("otp");
    expect(otpBoxes(f.b3, scan).map((b) => b.id)).toStrictEqual(["b0", "b1", "b2", "b3", "b4", "b5"]);
    // Two boxes alone are not a code.
    const g = page(`<input id="x" maxlength="1"><input id="y" maxlength="1">`, "x");
    expect(fieldKind(g.x, new Scan())).toBe(null);
  });
});

describe("cards", () => {
  test("autocomplete cc-* fields, and wording only in a form with a card number", () => {
    const f = page(
      `<form>
         <input id="num" autocomplete="cc-number"><input id="exp" autocomplete="cc-exp"><input id="csc" autocomplete="cc-csc">
       </form>
       <form><input id="n2" name="cardnumber"><label>Expiry (MM/YY) <input id="e2"></label><label>CVC <input id="c2" maxlength="4"></label><label>Name on card <input id="h2"></label></form>
       <form><label>Security code <input id="lone"></label></form>`,
      "num",
      "exp",
      "csc",
      "n2",
      "e2",
      "c2",
      "h2",
      "lone",
    );
    // "Security code" without a card number is not a card's code (here: a one-time code).
    expect(kinds(f)).toStrictEqual({ num: "card", exp: "card", csc: "card", n2: "card", e2: "card", c2: "card", h2: "card", lone: "otp" });
    expect(hasFields(new Scan(), "card")).toBe(true);
  });

  test("a security code in a password field is a card field, not a login", () => {
    const f = page(`<form><input id="n" autocomplete="cc-number"><input id="cvv" type="password" name="cvv"></form>`, "cvv");
    expect(kinds(f)).toStrictEqual({ cvv: "card" });
  });
});

describe("identities", () => {
  test("an address form: name, street, city and postal code are identity fields; its e-mail too", () => {
    const f = page(
      `<form><input id="fn" name="first_name"><input id="ln" name="last_name"><input id="st" autocomplete="address-line1"><input id="city" name="city"><input id="zip" name="zip"><input id="mail" type="email" name="email"></form>`,
      "fn",
      "ln",
      "st",
      "city",
      "zip",
      "mail",
    );
    expect(kinds(f)).toStrictEqual({ fn: "identity", ln: "identity", st: "identity", city: "identity", zip: "identity", mail: "identity" });
  });

  test("a lone e-mail field is the first step of a sign-in; a lone 'name' field is nothing", () => {
    const f = page(`<form><input id="mail" type="email" name="email"></form><form><input id="nm" name="name"></form>`, "mail", "nm");
    expect(kinds(f)).toStrictEqual({ mail: "login", nm: null });
  });

  test("in a sign-up form the user name field stays a login field; its name fields are identity fields", () => {
    const f = page(
      `<form><input id="fn" autocomplete="given-name"><input id="ln" autocomplete="family-name"><input id="mail" type="email" autocomplete="email"><input id="pw" type="password" autocomplete="new-password"></form>`,
      "fn",
      "ln",
      "mail",
      "pw",
    );
    expect(kinds(f)).toStrictEqual({ fn: "identity", ln: "identity", mail: "login", pw: "new-password" });
  });
});

describe("shadow roots and the cost of a scan", () => {
  test("fields inside a closed shadow root of a custom element are found through chrome.dom", () => {
    document.body.innerHTML = `<form id="f"><login-box id="box"></login-box></form>`;
    const host = document.getElementById("box")!;
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `<input id="u" name="username"><input id="p" type="password">`;
    const pw = root.getElementById("p") as HTMLInputElement;
    // Without chrome.dom the closed root stays closed.
    expect(new Scan().passwords()).toStrictEqual([]);
    vi.stubGlobal("chrome", { ...chrome, dom: { openOrClosedShadowRoot: (el: HTMLElement) => (el === host ? root : null) } });
    try {
      const scan = new Scan();
      expect(scan.passwords()).toStrictEqual([pw]);
      expect(usernameFieldFor(pw, scan)?.id).toBe("u");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  test("a container holds the fields inside shadow roots inside it", () => {
    document.body.innerHTML = `<div id="box"><span id="host"></span></div><input id="out" type="password">`;
    const root = document.getElementById("host")!.attachShadow({ mode: "open" });
    root.innerHTML = `<input id="in" type="password">`;
    const scan = new Scan();
    expect(scan.passwords(document.getElementById("box")).map((p) => p.id)).toStrictEqual(["in"]);
    expect(scan.passwords().map((p) => p.id)).toStrictEqual(["in", "out"]);
  });

  test("one scan walks the page once and works out each field's box and hint text once", () => {
    page(`<form><input id="u" name="user"><input id="p" type="password"><input id="q" type="password"></form>`);
    const boxes = vi.spyOn(Element.prototype, "getBoundingClientRect");
    const walks = vi.spyOn(document, "createTreeWalker");
    const scan = new Scan();
    for (let i = 0; i < 5; i++) {
      scan.passwords();
      loginPasswordField(scan);
      usernameFieldFor(scan.passwords()[0]!, scan);
    }
    // One walk of the document (labels add their own small walks: none here).
    expect(walks.mock.calls.filter(([root]) => root === document)).toHaveLength(1);
    // Three inputs: at most one visibility check each.
    expect(boxes.mock.calls.length).toBeLessThanOrEqual(3);
  });
});
