// C12: the popup shows the identity fields the web vault shows, with ID, passport and licence numbers masked.

import { emptyItem } from "@web/lib/types";
import { expect, test } from "vitest";
import { hostOf, parseUrl } from "../src/popup/ctx";
import { identityRows } from "../src/popup/identity";

test("identityRows: the web vault's fields and order; official numbers are secret", () => {
  const identity = {
    ...emptyItem("identity").identity!,
    title: "Dr",
    first_name: "Alex",
    middle_name: "J",
    last_name: "Morgan",
    email: "alex@example.com",
    phone: "+1 555 0100",
    company: "Example Ltd",
    address1: "1 Main St",
    address2: "Apt 4",
    city: "Springfield",
    state: "IL",
    postal_code: "62701",
    country: "US",
    username: "amorgan",
    ssn: "123-45-6789",
    passport_number: "X1234567",
    license_number: "D7654321",
  };
  expect(identityRows(identity)).toStrictEqual([
    { label: "Name", value: "Dr Alex J Morgan", secret: false },
    { label: "Email", value: "alex@example.com", secret: false },
    { label: "Phone", value: "+1 555 0100", secret: false },
    { label: "Company", value: "Example Ltd", secret: false },
    { label: "Address", value: "1 Main St, Apt 4, Springfield, IL, 62701, US", secret: false },
    { label: "Username", value: "amorgan", secret: false },
    { label: "National ID", value: "123-45-6789", secret: true },
    { label: "Passport number", value: "X1234567", secret: true },
    { label: "Licence number", value: "D7654321", secret: true },
  ]);
});

test("identityRows: empty fields are left out", () => {
  const identity = { ...emptyItem("identity").identity!, first_name: "Alex", passport_number: "X1" };
  expect(identityRows(identity).map((r) => r.label)).toStrictEqual(["Name", "Passport number"]);
});

test("C10: saved addresses that aren't valid URLs never throw in the popup", () => {
  expect(hostOf("https://my site")).toBe("");
  expect(hostOf("https://example.com/login")).toBe("example.com");
  expect(parseUrl("not a url")).toBe(null);
  expect(parseUrl("https://example.com")?.origin).toBe("https://example.com");
});
