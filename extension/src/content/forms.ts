/**
 * Card and identity (name and address) fields: which part of a card or identity a form field asks for, and the
 * value that goes into it (a <select> gets the value of its matching option). The autocomplete attribute decides
 * first. Without one, the field's hint text (fields.ts `Scan.hint`: name, id, placeholder, labels,
 * aria-labelledby, title) does, but only inside a form that has a card number field (cards) or two identity
 * fields (identities), so a lone "Name" or "Code" box elsewhere is never taken for one. A card's security code
 * goes only into a field that asks for exactly that. Pure DOM reads, no page writes: unit-tested in
 * test/forms.test.ts.
 */
import type { CardFill, IdentityFill } from "../shared/protocol";

export type Field = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

export type CardPart = "name" | "given" | "family" | "number" | "exp" | "exp-month" | "exp-year" | "csc" | "type";

export type IdentityPart = "name" | "title" | "given" | "middle" | "family" | "company" | "email" | "tel" | "street" | "address1" | "address2" | "city" | "state" | "postal" | "country" | "username";

/** The autofill field name of the autocomplete attribute ("section-x shipping street-address" → "street-address"), or "". */
export function autofillToken(el: Element): string {
  const tokens = (el.getAttribute("autocomplete") ?? "").toLowerCase().trim().split(/\s+/);
  return tokens.filter((t) => t && t !== "webauthn").at(-1) ?? "";
}

const CARD_TOKENS: Record<string, CardPart> = {
  "cc-name": "name",
  "cc-given-name": "given",
  "cc-family-name": "family",
  "cc-number": "number",
  "cc-exp": "exp",
  "cc-exp-month": "exp-month",
  "cc-exp-year": "exp-year",
  "cc-csc": "csc",
  "cc-type": "type",
};

/** Checked in this order: the more specific wording first ("expiry month" before "expiry", "card holder" before "card"). */
const CARD_HINTS: [CardPart, RegExp][] = [
  ["csc", /\b(cvc|cvv|cvn|csc|cid)\d?\b|security.?code|card.?code|card.?verification|verification.?(code|number|value)|sicherheitscode|pr[uü]fnummer|cryptogram/],
  ["exp-month", /exp\w*.?(month|mon|mm)\b|\b(month|mm).?exp|cc.?exp.?m|card.?month|ablaufmonat|mes.?(de.?)?(vencimiento|caducidad)/],
  ["exp-year", /exp\w*.?(year|yr|yy)|\b(year|yy).?exp|cc.?exp.?y|card.?year|ablaufjahr|a[nñ]o.?(de.?)?(vencimiento|caducidad)/],
  ["exp", /\bexp(iry|iration|ires)?.?(date)?\b|valid.?(thru|through|until)|\bmm.?\/?.?yy|ablaufdatum|g[uü]ltig.?bis|vencimiento|caducidad|date.?d.?expiration/],
  ["name", /card.?holder|holder.?name|name.?on.?(the.?)?card|cc.?name|card.?name|nameoncard|karteninhaber|titular/],
  ["type", /card.?(type|brand)|cc.?type|kartentyp/],
  ["number", /card.?(number|num|no\b|nr)|cc.?(number|num|no\b)|ccnum|cardnum|credit.?card|debit.?card|kartennummer|n[uú]mero.?(de.?)?(la.?)?tarjeta|num[eé]ro.?de.?carte/],
];

/** The card part `el` asks for by its autocomplete token, or by its hint text alone (the caller checks the form). */
function cardPartOf(el: Field, hint: string): { part: CardPart; byToken: boolean } | null {
  const token = autofillToken(el);
  if (token.startsWith("cc-")) {
    const part = CARD_TOKENS[token];
    return part ? { part, byToken: true } : null;
  }
  const matches = CARD_HINTS.filter(([, re]) => re.test(hint)).map(([part]) => part);
  const first = matches[0];
  if (!first) return null;
  // A security code only when nothing else matches too: "Card number / CVV" in one label is not a code field.
  if (first === "csc" && matches.length > 1) return null;
  return { part: first, byToken: false };
}

/** Whether `fields` (one form) has a card number field: only then do hint-text matches count as card fields. */
export function hasCardNumber(fields: readonly Field[], hint: (f: Field) => string): boolean {
  return fields.some((f) => cardPartOf(f, hint(f))?.part === "number");
}

/** The card part `el` asks for. `inCardForm`: whether its form has a card number field (hasCardNumber; asked only when needed). */
export function cardPart(el: Field, hint: string, inCardForm: () => boolean): CardPart | null {
  const found = cardPartOf(el, hint);
  if (!found || (!found.byToken && !inCardForm())) return null;
  // Card numbers, codes and dates are typed; a check box or a password-manager's own field isn't one.
  if (el instanceof HTMLInputElement && !CARD_INPUT_TYPES.has(el.type)) return null;
  return found.part;
}

const CARD_INPUT_TYPES = new Set(["text", "tel", "number", "password", "", "month"]);

const IDENTITY_TOKENS: Record<string, IdentityPart> = {
  name: "name",
  "honorific-prefix": "title",
  "given-name": "given",
  "additional-name": "middle",
  "family-name": "family",
  organization: "company",
  email: "email",
  tel: "tel",
  "tel-national": "tel",
  "street-address": "street",
  "address-line1": "address1",
  "address-line2": "address2",
  "address-level1": "state",
  "address-level2": "city",
  "postal-code": "postal",
  country: "country",
  "country-name": "country",
  username: "username",
};

/** In this order: e-mail before "address", the name parts before "name". */
const IDENTITY_HINTS: [IdentityPart, RegExp][] = [
  ["email", /e-?mail|courriel|correo/],
  ["tel", /phone|\btel\b|telephone|mobile|\bcell\b|handy|telefon|tel[eé]fono/],
  ["postal", /\bzip|postal|post.?code|\bplz\b|c[oó]digo.?postal|code.?postal/],
  ["country", /country|\bnation|\bland\b|pa[ií]s\b|\bpays\b/],
  ["state", /\bstate\b|province|\bregion\b|\bcounty\b|bundesland|provincia|prefecture/],
  ["city", /\bcity\b|\btown\b|locality|suburb|\bort\b|\bstadt\b|ciudad|\bville\b|municipality/],
  ["address2", /address.?(line)?.?2|addr.?2|apartment|\bapt\b|suite|\bunit\b|line.?2|adresszusatz|complemento/],
  ["address1", /address.?(line)?.?1|addr.?1|street|address|line.?1|stra(ss|ß)e|calle|direcci[oó]n|adresse/],
  ["company", /company|organi[sz]ation|business.?name|\bfirma\b|empresa|soci[eé]t[eé]/],
  ["given", /first.?name|given.?name|fore.?name|\bfname\b|vorname|pr[eé]nom|\bnombre\b/],
  ["middle", /middle.?name|\bmname\b|additional.?name/],
  ["family", /last.?name|family.?name|surname|\blname\b|nachname|apellido|nom.?de.?famille/],
  ["title", /honorific|salutation|anrede/],
  ["name", /full.?name|your.?name|recipient|\bname\b/],
];

/** Standard autofill field names that aren't identity parts. */
const OTHER_TOKENS =
  /^(cc-|new-password$|current-password$|one-time-code$|bday|sex$|url$|photo$|language$|transaction-|impp$|organization-title$|honorific-suffix$|nickname$|address-level[34]$|address-line3$|tel-(country-code|area-code|local|extension))/;

/** Hint text that names something else (a user name, a card): never an identity field by wording alone. */
const NOT_IDENTITY = /user|login|account|card|search|coupon|promo|captcha|password/;

const IDENTITY_INPUT_TYPES = new Set(["text", "email", "tel", "", "number"]);

/** The identity part `el` asks for, by its autocomplete token or its hint text (the caller checks the form for hint matches). */
function identityPartOf(el: Field, hint: string): { part: IdentityPart; byToken: boolean } | null {
  if (el instanceof HTMLInputElement && !IDENTITY_INPUT_TYPES.has(el.type)) return null;
  const token = autofillToken(el);
  const part = IDENTITY_TOKENS[token];
  if (part) return { part, byToken: true };
  // A token that names something else (a card field, a password, a one-time code) isn't overridden by wording;
  // "off" and made-up values ("nope", "chrome-off") say nothing, so the wording decides.
  if (OTHER_TOKENS.test(token)) return null;
  if (NOT_IDENTITY.test(hint)) return null;
  const found = IDENTITY_HINTS.find(([, re]) => re.test(hint));
  return found ? { part: found[0], byToken: false } : null;
}

/** How many different identity parts `fields` (one form) ask for: two or more make it an identity form. */
export function identityPartCount(fields: readonly Field[], hint: (f: Field) => string): number {
  const parts = new Set<IdentityPart>();
  for (const f of fields) {
    const p = identityPartOf(f, hint(f));
    if (p && p.part !== "username") parts.add(p.part);
  }
  return parts.size;
}

/** The identity part `el` asks for. `identityForm`: whether its form asks for two identity parts or more (identityPartCount; asked only when needed). */
export function identityPart(el: Field, hint: string, identityForm: () => boolean): IdentityPart | null {
  const found = identityPartOf(el, hint);
  if (!found || (!found.byToken && !identityForm())) return null;
  return found.part;
}

// ------------------------------------------------------------------ values

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];

/** 1–12 from "9", "09" or a month name; null otherwise. */
export function monthNumber(value: string): number | null {
  const v = value.trim().toLowerCase();
  if (/^\d{1,2}$/.test(v)) {
    const n = Number(v);
    return n >= 1 && n <= 12 ? n : null;
  }
  const i = MONTHS.findIndex((m) => v.length >= 3 && m.startsWith(v));
  return i >= 0 ? i + 1 : null;
}

/** A four-digit year from "2028" or "28"; null otherwise. */
export function fullYear(value: string): number | null {
  const v = value.trim();
  if (/^\d{4}$/.test(v)) return Number(v);
  if (/^\d{2}$/.test(v)) return 2000 + Number(v);
  return null;
}

const two = (n: number) => String(n).padStart(2, "0");
const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

/** The value of the first option of `select` that one of `wanted` describes (`match` decides), or null. */
function pickOption(select: HTMLSelectElement, match: (value: string, text: string) => boolean): string | null {
  for (const o of Array.from(select.options)) {
    if (o.disabled) continue;
    if (match(norm(o.value), norm(o.text))) return o.value;
  }
  return null;
}

/** "MM/YY" in the shape the field shows ("MM / YY", "MM/YYYY", "MMYY"). */
function expiryText(el: Field, hint: string, month: number, year: number): string {
  const placeholder = el.getAttribute("placeholder") ?? "";
  const shape = /\bmm(\s*[/\-. ]\s*|)(yyyy|yy|jjjj|jj|aaaa|aa)\b/i.exec(placeholder) ?? /\bmm(\s*[/\-. ]\s*|)(yyyy|yy|jjjj|jj|aaaa|aa)\b/i.exec(hint);
  const max = el instanceof HTMLSelectElement ? -1 : el.maxLength;
  const sep = shape ? (shape[1] ?? "/") : max === 4 || max === 6 ? "" : "/";
  const longYear = shape ? (shape[2] ?? "").length === 4 : max === 6 || max === 7;
  return `${two(month)}${sep}${longYear ? year : two(year % 100)}`;
}

const BRANDS: [string, RegExp][] = [
  ["Visa", /\bvisa\b/],
  ["Mastercard", /master.?card|\bmc\b/],
  ["American Express", /american.?express|\bamex\b/],
  ["Discover", /discover/],
  ["Diners Club", /diners/],
  ["JCB", /\bjcb\b/],
  ["UnionPay", /union.?pay/],
  ["Maestro", /maestro/],
];

/** The value for a card part, or null when the card has none or the field can't take it. */
export function cardValue(part: CardPart, card: CardFill, el: Field, hint = ""): string | null {
  const month = monthNumber(card.expMonth);
  const year = fullYear(card.expYear);
  const select = el instanceof HTMLSelectElement ? el : null;
  const maxLength = select ? -1 : (el as HTMLInputElement | HTMLTextAreaElement).maxLength;
  const holder = card.name.trim();
  switch (part) {
    case "name":
      return holder || null;
    case "given":
      return holder ? holder.split(/\s+/).slice(0, -1).join(" ") || holder : null;
    case "family":
      return holder.includes(" ") ? (holder.split(/\s+/).at(-1) ?? null) : null;
    case "number": {
      const digits = card.number.replace(/\D/g, "");
      if (!digits || select) return null;
      return maxLength > 0 && maxLength < digits.length ? null : digits;
    }
    case "exp":
      return month && year && !select ? expiryText(el, hint, month, year) : null;
    case "exp-month":
      if (!month) return null;
      if (select) return pickOption(select, (v, t) => monthNumber(v) === month || monthNumber(t) === month || Number(/^\d{1,2}/.exec(t)?.[0]) === month);
      return two(month);
    case "exp-year":
      if (!year) return null;
      if (select) return pickOption(select, (v, t) => fullYear(v) === year || fullYear(t) === year);
      return maxLength === 2 || /\byy\b/i.test(el.getAttribute("placeholder") ?? "") ? two(year % 100) : String(year);
    case "csc": {
      // Only a field that takes a code of this length (a maxlength of 3 or 4, or none).
      const code = card.code.replace(/\s/g, "");
      if (!/^\d{3,4}$/.test(code) || select) return null;
      return maxLength > 0 && maxLength < code.length ? null : code;
    }
    case "type": {
      const brand = card.brand.trim();
      if (!brand) return null;
      if (!select) return brand;
      const re = BRANDS.find(([, r]) => r.test(norm(brand)))?.[1];
      return pickOption(select, (v, t) => (re ? re.test(v) || re.test(t) : v === norm(brand) || t === norm(brand)));
    }
  }
}

/** Country names for a two-letter code (in English and the browser's language), for country selects that list names. */
function countryNames(code: string): string[] {
  if (!/^[a-z]{2}$/i.test(code)) return [];
  const out: string[] = [];
  for (const lang of new Set(["en", navigator.language])) {
    try {
      const name = new Intl.DisplayNames([lang], { type: "region" }).of(code.toUpperCase());
      if (name && name.toUpperCase() !== code.toUpperCase()) out.push(norm(name));
    } catch {
      /* no names for this language */
    }
  }
  return out;
}

/** The value for an identity part, or null when the identity has none or the field can't take it. */
export function identityValue(part: IdentityPart, id: IdentityFill, el: Field): string | null {
  const select = el instanceof HTMLSelectElement ? el : null;
  const pick = (value: string, extra: string[] = []) => {
    if (!value.trim()) return null;
    if (!select) return value;
    const wanted = new Set([norm(value), ...extra]);
    return pickOption(select, (v, t) => wanted.has(v) || wanted.has(t));
  };
  switch (part) {
    case "name":
      return pick(
        [id.first_name, id.middle_name, id.last_name]
          .map((s) => s.trim())
          .filter(Boolean)
          .join(" "),
      );
    case "title":
      return pick(id.title, [norm(id.title).replace(/\.$/, ""), `${norm(id.title).replace(/\.$/, "")}.`]);
    case "given":
      return pick(id.first_name);
    case "middle":
      return pick(id.middle_name);
    case "family":
      return pick(id.last_name);
    case "company":
      return pick(id.company);
    case "email":
      return pick(id.email);
    case "tel":
      return pick(id.phone);
    case "street": {
      const lines = [id.address1, id.address2].map((s) => s.trim()).filter(Boolean);
      return lines.length && !select ? lines.join(el instanceof HTMLTextAreaElement ? "\n" : ", ") : null;
    }
    case "address1":
      return pick(id.address1);
    case "address2":
      return pick(id.address2);
    case "city":
      return pick(id.city);
    case "state":
      return pick(id.state);
    case "postal":
      return pick(id.postal_code);
    case "country": {
      const country = id.country.trim();
      if (!country || !select) return country || null;
      // The identity may hold a code ("DE") or a name ("Germany"); the select may list either.
      const names = countryNames(country);
      const found = pick(country, names);
      if (found !== null) return found;
      return pickOption(select, (v) => countryNames(v).includes(norm(country)));
    }
    case "username":
      return pick(id.username);
  }
}
