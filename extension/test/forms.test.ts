// @vitest-environment happy-dom
// @vitest-environment-options {"url": "https://shop.example/checkout"}
// Card and identity filling, page side (content/forms.ts mapping, content/fill.ts commands; D11), the login fill's
// field choice (never a new-password field; split one-time-code boxes), "Use a strong password" (D1) and fill focus
// (D8: input and change events, the focus stays in the last field filled).

import { describe, expect, test } from "vitest";
import { fillCard, fillGenerated, fillIdentity, fillLogin } from "../src/content/fill";
import { cardValue, identityValue, monthNumber } from "../src/content/forms";
import type { CardFill, FillCommand, IdentityFill } from "../src/shared/protocol";
import { fakeLayout, page } from "./dom";

fakeLayout();

const CARD: CardFill = { name: "Alex Morgan", number: "4242 4242 4242 4242", expMonth: "9", expYear: "2028", code: "123", brand: "Visa" };
const IDENTITY: IdentityFill = {
  title: "Mx",
  first_name: "Alex",
  middle_name: "",
  last_name: "Morgan",
  company: "Copperleaf",
  email: "alex@example.com",
  phone: "+1 555 0100",
  address1: "1 Main St",
  address2: "Apt 4",
  city: "Springfield",
  state: "CA",
  postal_code: "94000",
  country: "DE",
  username: "alexm",
};

const el = <T extends HTMLElement = HTMLInputElement>(html: string): T => {
  document.body.innerHTML = html;
  return document.body.firstElementChild as T;
};

describe("card values", () => {
  test("the expiry date in the shape the field shows", () => {
    expect(cardValue("exp", CARD, el(`<input placeholder="MM / YY">`))).toBe("09 / 28");
    expect(cardValue("exp", CARD, el(`<input placeholder="MM/YYYY">`))).toBe("09/2028");
    expect(cardValue("exp", CARD, el(`<input maxlength="4">`))).toBe("0928");
    expect(cardValue("exp", CARD, el(`<input>`))).toBe("09/28");
  });

  test("month and year selects take the matching option, whatever its wording", () => {
    const months = Array.from({ length: 12 }, (_, i) => `<option value="m${i + 1}">${String(i + 1).padStart(2, "0")} - ${new Date(2000, i, 1).toLocaleString("en", { month: "long" })}</option>`).join(
      "",
    );
    expect(cardValue("exp-month", CARD, el(`<select><option value="">Month</option>${months}</select>`))).toBe("m9");
    expect(cardValue("exp-month", CARD, el(`<select><option>Jan</option><option>Sep</option></select>`))).toBe("Sep");
    expect(cardValue("exp-year", CARD, el(`<select><option value="27">27</option><option value="28">28</option></select>`))).toBe("28");
    expect(cardValue("exp-year", CARD, el(`<select><option value="y1">2027</option><option value="y2">2028</option></select>`))).toBe("y2");
    expect(cardValue("exp-year", CARD, el(`<input maxlength="2">`))).toBe("28");
    expect(cardValue("exp-year", CARD, el(`<input>`))).toBe("2028");
    expect(monthNumber("September")).toBe(9);
  });

  test("the number without spaces; the security code only when it fits", () => {
    expect(cardValue("number", CARD, el(`<input>`))).toBe("4242424242424242");
    expect(cardValue("number", CARD, el(`<input maxlength="12">`))).toBe(null);
    expect(cardValue("csc", CARD, el(`<input maxlength="4">`))).toBe("123");
    expect(cardValue("csc", CARD, el(`<input maxlength="2">`))).toBe(null);
    expect(cardValue("csc", { ...CARD, code: "" }, el(`<input>`))).toBe(null);
  });

  test("the card type select by brand name or abbreviation", () => {
    expect(cardValue("type", CARD, el(`<select><option value="mc">MasterCard</option><option value="vi">VISA</option></select>`))).toBe("vi");
    expect(cardValue("type", { ...CARD, brand: "American Express" }, el(`<select><option value="AMEX">Amex</option></select>`))).toBe("AMEX");
  });
});

describe("identity values", () => {
  test("full name, street address in one field or two lines, country by code or name", () => {
    expect(identityValue("name", IDENTITY, el(`<input>`))).toBe("Alex Morgan");
    expect(identityValue("street", IDENTITY, el(`<input>`))).toBe("1 Main St, Apt 4");
    expect(identityValue("street", IDENTITY, el(`<textarea></textarea>`))).toBe("1 Main St\nApt 4");
    expect(identityValue("country", IDENTITY, el(`<select><option value="FR">France</option><option value="DE">Germany</option></select>`))).toBe("DE");
    expect(identityValue("country", IDENTITY, el(`<select><option value="fr">France</option><option value="de-x">Germany</option></select>`))).toBe("de-x");
    // A name in the identity, codes in the select: the option whose code is that country.
    expect(identityValue("country", { ...IDENTITY, country: "Germany" }, el(`<select><option value="FR">France</option><option value="DE">Deutschland (DE)</option></select>`))).toBe("DE");
    expect(identityValue("country", { ...IDENTITY, country: "Atlantis" }, el(`<select><option value="FR">France</option><option value="DE">Germany</option></select>`))).toBe(null);
    expect(identityValue("state", IDENTITY, el(`<select><option value="NY">New York</option><option value="CA">California</option></select>`))).toBe("CA");
    expect(identityValue("address2", { ...IDENTITY, address2: "" }, el(`<input>`))).toBe(null);
  });
});

describe("fill commands in the page", () => {
  test("fill:card fills a checkout form; the security code only into its own field; the focus ends in the last field", () => {
    const f = page(
      `<form>
        <label>Name on card <input id="name"></label>
        <input id="num" autocomplete="cc-number">
        <select id="mm" autocomplete="cc-exp-month"><option value="">MM</option><option value="09">09</option></select>
        <select id="yy" autocomplete="cc-exp-year"><option value="">YY</option><option value="2028">2028</option></select>
        <label>Promo code <input id="promo"></label>
        <input id="cvc" autocomplete="cc-csc">
      </form>`,
      "name",
      "num",
      "mm",
      "yy",
      "promo",
      "cvc",
    );
    const events: string[] = [];
    f.num.addEventListener("input", () => events.push("input"));
    f.num.addEventListener("change", () => events.push("change"));
    expect(fillCard({ card: CARD, origin: "https://shop.example", focused: false })).toBe(true);
    expect([f.name.value, f.num.value, f.mm.value, f.yy.value, f.promo.value, f.cvc.value]).toStrictEqual(["Alex Morgan", "4242424242424242", "09", "2028", "", "123"]);
    expect(events).toStrictEqual(["input", "change"]);
    expect(document.activeElement).toBe(f.cvc);
  });

  test("fill:card goes only to the origin the background checked, and only over https (checked again in the page)", () => {
    page(`<input autocomplete="cc-number">`);
    // Another origin of the same site (the frame navigated after the check): nothing.
    expect(fillCard({ card: CARD, origin: "https://pay.shop.example", focused: false })).toBe(false);
    expect(fillCard({ card: CARD, origin: "http://shop.example", focused: false })).toBe(false);
    expect(fillCard({ card: CARD, origin: 42 as unknown as string, focused: false })).toBe(false);
    Object.defineProperty(globalThis, "origin", { value: "http://shop.example", configurable: true, writable: true });
    expect(fillCard({ card: CARD, origin: "http://shop.example", focused: false })).toBe(false);
  });

  test("fill:identity fills the address form and never ID numbers (they aren't in the command)", () => {
    const f = page(
      `<form><input id="fn" autocomplete="given-name"><input id="ln" autocomplete="family-name"><input id="mail" autocomplete="email">
       <input id="st" name="street"><input id="city" name="city"><input id="zip" name="postal_code">
       <select id="country" name="country"><option value="US">United States</option><option value="DE">Germany</option></select></form>`,
      "fn",
      "ln",
      "mail",
      "st",
      "city",
      "zip",
      "country",
    );
    expect(fillIdentity({ identity: IDENTITY, origin: "https://shop.example", focused: false })).toBe(true);
    expect(Object.values(f).map((x) => x.value)).toStrictEqual(["Alex", "Morgan", "alex@example.com", "1 Main St", "Springfield", "94000", "DE"]);
  });

  const login = (over: Partial<FillCommand> = {}): FillCommand => ({
    username: "alex",
    password: "secret-pw",
    origin: "https://shop.example",
    focused: false,
    ...over,
  });

  test("a saved login never goes into a new-password field; the focus stays in the last field filled", () => {
    const f = page(
      `<form><input id="user" name="username"><input id="cur" type="password" autocomplete="current-password"><input id="new" type="password" autocomplete="new-password"></form>`,
      "user",
      "cur",
      "new",
    );
    expect(fillLogin(login())).toBe(true);
    expect([f.user.value, f.cur.value, f.new.value]).toStrictEqual(["alex", "secret-pw", ""]);
    expect(document.activeElement).toBe(f.cur);
    // A sign-up form: the user name only.
    const g = page(`<form><input id="user" name="username"><input id="new" type="password" autocomplete="new-password"></form>`, "user", "new");
    expect(fillLogin(login())).toBe(true);
    expect([g.user.value, g.new.value]).toStrictEqual(["alex", ""]);
  });

  test("a login checked for another origin isn't filled (the page compares its own origin, no site rules)", () => {
    page(`<form><input name="username"><input type="password"></form>`);
    expect(fillLogin(login({ origin: "https://bank.example" }))).toBe(false);
    expect(fillLogin(login({ origin: "https://login.shop.example" }))).toBe(false);
    expect(fillLogin(login({ origin: "http://shop.example" }))).toBe(false);
    expect(fillLogin(login())).toBe(true);
  });

  test("a one-time code alone goes across split boxes", () => {
    const boxes = Array.from({ length: 6 }, (_, i) => `<input id="b${i}" maxlength="1">`).join("");
    page(`<form>${boxes}</form>`);
    expect(fillLogin(login({ username: "", password: "", totp: "123456" }))).toBe(true);
    expect([...document.querySelectorAll("input")].map((i) => i.value).join("")).toBe("123456");
    expect(document.activeElement?.id).toBe("b5");
  });

  test("fill:generated needs the inline menu's new-password field (none here: nothing is filled)", () => {
    page(`<form><input name="email"><input type="password" autocomplete="new-password"></form>`);
    expect(fillGenerated("Gen-erated-1", "https://shop.example")).toStrictEqual({ filled: false, username: "" });
  });
});
